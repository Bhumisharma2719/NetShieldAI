from fastapi import APIRouter, Query

from app.services.live_traffic_store import get_latest_live_logs

router = APIRouter(tags=["live-traffic"])


@router.get("/live-traffic")
async def live_traffic(limit: int = Query(default=20, ge=1, le=100)):
    try:
        records = get_latest_live_logs(limit=limit)
    except Exception as exc:
        return {
            "records": [],
            "count": 0,
            "error": f"Unable to read live traffic store: {exc}",
        }

    high_risk_count = sum(1 for record in records if record.get("risk_label") == "HIGH-RISK")
    anomaly_count = sum(1 for record in records if record.get("prediction") == 1)

    return {
        "records": records,
        "count": len(records),
        "high_risk_count": high_risk_count,
        "anomaly_count": anomaly_count,
    }
