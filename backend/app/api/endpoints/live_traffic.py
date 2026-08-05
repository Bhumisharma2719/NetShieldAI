import csv
import json
from io import StringIO

from fastapi import APIRouter, Query
from fastapi.responses import Response

from app.services.live_traffic_store import get_all_live_logs, get_alerts_history, get_latest_live_logs

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


@router.get("/live-traffic/export")
async def export_live_traffic_report():
    try:
        records = get_all_live_logs()
        output = StringIO()
        writer = csv.DictWriter(
            output,
            fieldnames=[
                "Timestamp",
                "Source IP",
                "Destination IP",
                "Protocol",
                "Packets",
                "Bytes",
                "Risk Score (%)",
                "Risk Category",
            ],
        )
        writer.writeheader()

        for record in records:
            writer.writerow(
                {
                    "Timestamp": record.get("timestamp", ""),
                    "Source IP": record.get("src_ip", ""),
                    "Destination IP": record.get("dst_ip", ""),
                    "Protocol": str(record.get("proto", "")).upper(),
                    "Packets": record.get("packets", 0),
                    "Bytes": record.get("bytes", 0),
                    "Risk Score (%)": record.get("risk_score", 0),
                    "Risk Category": record.get("risk_label") or record.get("label", ""),
                }
            )
    except Exception as exc:
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(["Timestamp", "Source IP", "Destination IP", "Protocol", "Packets", "Bytes", "Risk Score (%)", "Risk Category"])
        writer.writerow(["EXPORT_ERROR", "", "", "", "", "", "", f"Unable to export live traffic: {exc}"])

    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="NetShield_Security_Audit_Report.csv"'},
    )


@router.get("/live-traffic/logs")
async def download_threat_intelligence_log():
    try:
        records = get_all_live_logs()
        content = json.dumps(records, ensure_ascii=False, indent=2)
    except Exception as exc:
        content = json.dumps(
            {
                "error": f"Unable to export live traffic log: {exc}",
            },
            ensure_ascii=False,
            indent=2,
        )

    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="NetShield_Threat_Intelligence_Log.json"'},
    )


@router.get("/live-traffic/alerts-history")
async def alerts_history():
    try:
        records = get_alerts_history()
        if not records:
            live_records = get_all_live_logs()
            records = [
                {
                    "timestamp": record.get("timestamp"),
                    "src_ip": record.get("src_ip"),
                    "dst_ip": record.get("dst_ip"),
                    "protocol": record.get("protocol") or record.get("proto"),
                    "risk_score": record.get("risk_score", 0),
                    "attack_type": record.get("attack_type") or record.get("attack_cat") or "High Risk",
                }
                for record in live_records
                if _safe_risk_score(record.get("risk_score", 0)) >= 70
            ]
    except Exception as exc:
        return {"records": [], "count": 0, "error": f"Unable to read alerts history: {exc}"}

    records = sorted(records, key=lambda item: str(item.get("timestamp", "")), reverse=True)
    return {"records": records, "count": len(records)}


def _safe_risk_score(value) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0
