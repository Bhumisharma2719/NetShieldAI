from fastapi import APIRouter, Query

from app.services.traffic_data import get_records, get_summary

router = APIRouter(prefix="/traffic", tags=["traffic"])


@router.get("/records")
async def traffic_records(
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
):
    return await get_records(offset=offset, limit=limit)


@router.get("/summary")
async def traffic_summary():
    return await get_summary()
