from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any

BACKEND_DIR = Path(__file__).resolve().parents[2]
LIVE_TRAFFIC_PATH = BACKEND_DIR / "ml_core" / "live_traffic.json"
MAX_LIVE_RECORDS = 500

_write_lock = threading.Lock()


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

    return [item for item in data if isinstance(item, dict)]


def append_live_log(record: dict[str, Any], max_records: int = MAX_LIVE_RECORDS) -> None:
    LIVE_TRAFFIC_PATH.parent.mkdir(parents=True, exist_ok=True)

    with _write_lock:
        records = _read_records_unlocked()
        records.append(record)
        records = records[-max_records:]

        temp_path = LIVE_TRAFFIC_PATH.with_suffix(".tmp")
        with temp_path.open("w", encoding="utf-8") as file:
            json.dump(records, file, ensure_ascii=False, indent=2)

        os.replace(temp_path, LIVE_TRAFFIC_PATH)


def get_latest_live_logs(limit: int = 20) -> list[dict[str, Any]]:
    limit = max(1, min(limit, MAX_LIVE_RECORDS))
    records = _read_records_unlocked()
    return list(reversed(records[-limit:]))
