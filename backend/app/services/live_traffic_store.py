from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

BACKEND_DIR = Path(__file__).resolve().parents[2]
LIVE_TRAFFIC_PATH = BACKEND_DIR / "ml_core" / "live_traffic.json"
ALERTS_HISTORY_PATH = BACKEND_DIR / "ml_core" / "alerts_history.json"
LIVE_CAPTURE_STATS_PATH = BACKEND_DIR / "ml_core" / "live_capture_stats.json"
MAX_LIVE_RECORDS = 500
MAX_ALERT_HISTORY = 2000
LIVE_RECORD_STALE_SECONDS = max(1, int(os.getenv("LIVE_TRAFFIC_STALE_SECONDS", "10")))
LIVE_CAPTURE_IDLE_SECONDS = max(1, int(os.getenv("LIVE_CAPTURE_IDLE_SECONDS", "2")))

_write_lock = threading.RLock()

COMMON_WEB_PORTS = {80, 443, 8080, 8443}
COMMON_SERVICE_PORTS = {21, 22, 25, 53, 67, 68, 110, 123, 143, 389, 465, 587, 993, 995}


def classify_attack_type(record: dict[str, Any]) -> str:
    try:
        risk_score = float(record.get("risk_score", 0) or 0)
    except (TypeError, ValueError):
        risk_score = 0.0

    proto = str(record.get("proto", "") or "").lower()
    packets = int(record.get("packets", 0) or 0)
    bytes_count = int(record.get("bytes", 0) or 0)
    duration = float(record.get("dur", 0) or 0)
    dst_port = int(record.get("dst_port", 0) or 0)

    if risk_score < 40:
        return "Normal Traffic"

    if proto == "tcp" and (packets >= 40 or bytes_count >= 150_000 or (duration > 0 and packets / max(duration, 0.001) >= 45)):
        return "DDoS / SYN Flood"

    if packets <= 12 and (proto in {"tcp", "udp", "icmp"} or dst_port in COMMON_SERVICE_PORTS):
        return "Port Scanning / Recon"

    if proto == "icmp" or dst_port in COMMON_WEB_PORTS or dst_port in COMMON_SERVICE_PORTS:
        return "Exploit / Protocol Anomaly"

    if proto == "udp" and (packets >= 24 or bytes_count >= 80_000):
        return "DDoS / SYN Flood"

    return "Exploit / Protocol Anomaly"


def normalize_live_record(record: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(record)
    normalized["protocol"] = normalized.get("protocol") or normalized.get("proto")
    normalized["attack_type"] = normalized.get("attack_type") or classify_attack_type(normalized)
    normalized["capture_source"] = normalized.get("capture_source") or "real-live-sniffer"
    return normalized


def _read_records_unlocked() -> list[dict[str, Any]]:
    if not LIVE_TRAFFIC_PATH.exists():
        return []

    try:
        with LIVE_TRAFFIC_PATH.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except (json.JSONDecodeError, OSError):
        return []

    if not isinstance(data, list):
        return []

    return [normalize_live_record(item) for item in data if isinstance(item, dict)]


def append_live_log(record: dict[str, Any], max_records: int = MAX_LIVE_RECORDS) -> None:
    LIVE_TRAFFIC_PATH.parent.mkdir(parents=True, exist_ok=True)

    with _write_lock:
        normalized = normalize_live_record(record)
        records = _read_records_unlocked()
        records.append(normalized)
        records = records[-max_records:]

        temp_path = LIVE_TRAFFIC_PATH.with_suffix(".tmp")
        with temp_path.open("w", encoding="utf-8") as file:
            json.dump(records, file, ensure_ascii=False, indent=2)

        os.replace(temp_path, LIVE_TRAFFIC_PATH)

        stats = get_live_capture_stats()
        stats["total_captured_packets"] = int(stats.get("total_captured_packets", 0) or 0) + 1
        stats["last_capture_at"] = normalized.get("timestamp")
        _write_live_capture_stats(stats)

        try:
            risk_score = float(normalized.get("risk_score", 0) or 0)
        except (TypeError, ValueError):
            risk_score = 0.0

        if risk_score >= 70:
            append_alert_history(
                {
                    "timestamp": normalized.get("timestamp"),
                    "src_ip": normalized.get("src_ip"),
                    "dst_ip": normalized.get("dst_ip"),
                    "protocol": normalized.get("protocol") or normalized.get("proto"),
                    "risk_score": round(risk_score, 1),
                    "attack_type": normalized.get("attack_type"),
                }
            )


def clear_live_traffic_store() -> None:
    LIVE_TRAFFIC_PATH.parent.mkdir(parents=True, exist_ok=True)

    with _write_lock:
        temp_path = LIVE_TRAFFIC_PATH.with_suffix(".tmp")
        with temp_path.open("w", encoding="utf-8") as file:
            json.dump([], file, ensure_ascii=False, indent=2)

        os.replace(temp_path, LIVE_TRAFFIC_PATH)
        _write_live_capture_stats({"total_captured_packets": 0, "last_capture_at": None})


def clear_alert_history_store() -> None:
    ALERTS_HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)

    with _write_lock:
        temp_path = ALERTS_HISTORY_PATH.with_suffix(".tmp")
        with temp_path.open("w", encoding="utf-8") as file:
            json.dump([], file, ensure_ascii=False, indent=2)

        os.replace(temp_path, ALERTS_HISTORY_PATH)


def clear_live_capture_storage() -> None:
    clear_live_traffic_store()
    clear_alert_history_store()


def _parse_timestamp(value: Any) -> datetime | None:
    if not value:
        return None

    if isinstance(value, datetime):
        timestamp = value
    else:
        raw_value = str(value).strip()
        if not raw_value:
            return None
        raw_value = raw_value.replace("Z", "+00:00")
        try:
            timestamp = datetime.fromisoformat(raw_value)
        except ValueError:
            return None

    if timestamp.tzinfo is None:
        return timestamp.replace(tzinfo=timezone.utc)

    return timestamp.astimezone(timezone.utc)


def _filter_fresh_records(records: list[dict[str, Any]], max_age_seconds: int) -> list[dict[str, Any]]:
    if max_age_seconds <= 0:
        return records

    now = datetime.now(timezone.utc)
    fresh_records: list[dict[str, Any]] = []

    for record in records:
        timestamp = _parse_timestamp(record.get("timestamp"))
        if timestamp is None:
            continue

        if (now - timestamp).total_seconds() <= max_age_seconds:
            fresh_records.append(record)

    return fresh_records


def _capture_is_active() -> bool:
    stats = get_live_capture_stats()
    last_capture_at = stats.get("last_capture_at")
    timestamp = _parse_timestamp(last_capture_at)
    if timestamp is None:
        return False

    now = datetime.now(timezone.utc)
    return (now - timestamp).total_seconds() <= LIVE_CAPTURE_IDLE_SECONDS


def get_latest_live_logs(limit: int = 20, max_age_seconds: int | None = LIVE_RECORD_STALE_SECONDS) -> list[dict[str, Any]]:
    if not _capture_is_active():
        return []

    limit = max(1, min(limit, MAX_LIVE_RECORDS))
    records = _read_records_unlocked()
    if max_age_seconds is not None:
        records = _filter_fresh_records(records, max_age_seconds)
    return list(reversed(records[-limit:]))


def get_all_live_logs(max_age_seconds: int | None = None) -> list[dict[str, Any]]:
    if not _capture_is_active():
        return []

    records = _read_records_unlocked()
    if max_age_seconds is not None:
        records = _filter_fresh_records(records, max_age_seconds)
    return records


def _read_live_capture_stats_unlocked() -> dict[str, Any]:
    if not LIVE_CAPTURE_STATS_PATH.exists():
        return {"total_captured_packets": 0, "last_capture_at": None}

    try:
        with LIVE_CAPTURE_STATS_PATH.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except (json.JSONDecodeError, OSError):
        return {"total_captured_packets": 0, "last_capture_at": None}

    if not isinstance(data, dict):
        return {"total_captured_packets": 0, "last_capture_at": None}

    return {
        "total_captured_packets": int(data.get("total_captured_packets", 0) or 0),
        "last_capture_at": data.get("last_capture_at"),
    }


def _write_live_capture_stats(stats: dict[str, Any]) -> None:
    LIVE_CAPTURE_STATS_PATH.parent.mkdir(parents=True, exist_ok=True)

    temp_path = LIVE_CAPTURE_STATS_PATH.with_suffix(".tmp")
    with temp_path.open("w", encoding="utf-8") as file:
        json.dump(
            {
                "total_captured_packets": int(stats.get("total_captured_packets", 0) or 0),
                "last_capture_at": stats.get("last_capture_at"),
            },
            file,
            ensure_ascii=False,
            indent=2,
        )

    os.replace(temp_path, LIVE_CAPTURE_STATS_PATH)


def get_live_capture_stats() -> dict[str, Any]:
    with _write_lock:
        return _read_live_capture_stats_unlocked()


def _read_alert_history_unlocked() -> list[dict[str, Any]]:
    if not ALERTS_HISTORY_PATH.exists():
        return []

    try:
        with ALERTS_HISTORY_PATH.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except (json.JSONDecodeError, OSError):
        return []

    if not isinstance(data, list):
        return []

    return [item for item in data if isinstance(item, dict)]


def append_alert_history(alert_record: dict[str, Any], max_records: int = MAX_ALERT_HISTORY) -> None:
    ALERTS_HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)

    with _write_lock:
        alerts = _read_alert_history_unlocked()
        alerts.append(dict(alert_record))
        alerts = alerts[-max_records:]

        temp_path = ALERTS_HISTORY_PATH.with_suffix(".tmp")
        with temp_path.open("w", encoding="utf-8") as file:
            json.dump(alerts, file, ensure_ascii=False, indent=2)

        os.replace(temp_path, ALERTS_HISTORY_PATH)


def get_alerts_history() -> list[dict[str, Any]]:
    return list(reversed(_read_alert_history_unlocked()))
