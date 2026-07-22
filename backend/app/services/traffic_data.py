from datetime import datetime
from typing import Any

from sqlalchemy import text

from app.db.postgres import get_sessionmaker


def row_to_dict(row: Any) -> dict[str, Any]:
    data = dict(row._mapping)
    timestamp = data.get("timestamp")
    if timestamp is not None and hasattr(timestamp, "isoformat"):
        data["timestamp"] = timestamp.isoformat()
    return data


async def get_records(offset: int = 0, limit: int = 50) -> dict[str, Any]:
    safe_offset = max(offset, 0)
    safe_limit = min(max(limit, 1), 200)
    sessionmaker = get_sessionmaker()

    async with sessionmaker() as session:
        total_result = await session.execute(text("SELECT COUNT(*) AS total FROM network_logs"))
        total = int(total_result.scalar() or 0)
        if total and safe_offset >= total:
            safe_offset = 0

        result = await session.execute(
            text(
                """
                SELECT
                    id,
                    timestamp,
                    src_ip,
                    dst_ip,
                    proto,
                    service,
                    state,
                    duration,
                    spkts,
                    dpkts,
                    packets,
                    sbytes,
                    dbytes,
                    bytes,
                    rate,
                    attack_cat,
                    label
                FROM network_logs
                ORDER BY id
                OFFSET :offset
                LIMIT :limit
                """
            ),
            {"offset": safe_offset, "limit": safe_limit},
        )
        records = [row_to_dict(row) for row in result.fetchall()]

    next_offset = safe_offset + safe_limit
    if total:
        next_offset = next_offset % total

    return {"total": total, "offset": safe_offset, "limit": safe_limit, "next_offset": next_offset, "records": records}


async def get_summary() -> dict[str, Any]:
    sessionmaker = get_sessionmaker()

    async with sessionmaker() as session:
        totals_result = await session.execute(
            text(
                """
                SELECT
                    COUNT(*) AS flows,
                    COALESCE(SUM(packets), 0) AS packets,
                    COALESCE(SUM(bytes), 0) AS bytes,
                    COALESCE(SUM(label), 0) AS attacks
                FROM network_logs
                """
            )
        )
        totals = row_to_dict(totals_result.first())

        attack_result = await session.execute(
            text(
                """
                SELECT COALESCE(attack_cat, 'Unknown') AS name, COUNT(*) AS value
                FROM network_logs
                GROUP BY COALESCE(attack_cat, 'Unknown')
                ORDER BY value DESC
                """
            )
        )
        protocol_result = await session.execute(
            text(
                """
                SELECT COALESCE(proto, 'unknown') AS name, COUNT(*) AS value
                FROM network_logs
                GROUP BY COALESCE(proto, 'unknown')
                ORDER BY value DESC
                """
            )
        )
        trend_result = await session.execute(
            text(
                """
                SELECT
                    to_char(date_trunc('minute', timestamp), 'HH24:MI') AS time,
                    COALESCE(SUM(packets), 0) AS packets,
                    COUNT(*) AS flows,
                    COALESCE(SUM(label), 0) AS attacks
                FROM network_logs
                GROUP BY date_trunc('minute', timestamp)
                ORDER BY date_trunc('minute', timestamp)
                LIMIT 24
                """
            )
        )

    return {
        "dataset": "network_logs",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "totals": {
            "flows": int(totals.get("flows") or 0),
            "packets": int(totals.get("packets") or 0),
            "bytes": int(totals.get("bytes") or 0),
            "attacks": int(totals.get("attacks") or 0),
        },
        "attack_distribution": [row_to_dict(row) for row in attack_result.fetchall()],
        "protocol_distribution": [row_to_dict(row) for row in protocol_result.fetchall()],
        "traffic_trend": [row_to_dict(row) for row in trend_result.fetchall()],
    }
