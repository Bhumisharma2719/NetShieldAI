from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any

BACKEND_DIR = Path(__file__).resolve().parents[2]
LIVE_TRAFFIC_PATH = BACKEND_DIR / "ml_core" / "live_traffic.json"
ALERTS_HISTORY_PATH = BACKEND_DIR / "ml_core" / "alerts_history.json"
MAX_LIVE_RECORDS = 500
MAX_ALERT_HISTORY = 2000

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


def get_latest_live_logs(limit: int = 20) -> list[dict[str, Any]]:
    limit = max(1, min(limit, MAX_LIVE_RECORDS))
    records = _read_records_unlocked()
    return list(reversed(records[-limit:]))


def get_all_live_logs() -> list[dict[str, Any]]:
    return _read_records_unlocked()


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
