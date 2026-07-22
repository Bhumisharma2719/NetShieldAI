from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from app.services.anomaly_service import ModelNotFoundError, anomaly_service

router = APIRouter(prefix="/predict", tags=["prediction"])


class PredictionRequest(BaseModel):
    packets: int = Field(..., ge=0, description="Total packet count for this traffic flow")
    bytes: int = Field(..., ge=0, description="Total byte count for this traffic flow")


class PredictionResponse(BaseModel):
    prediction: int
    label: str
    risk_score: float


@router.post("/check", response_model=PredictionResponse)
async def check_anomaly(payload: PredictionRequest):
    try:
        return anomaly_service.predict(packets=payload.packets, bytes_value=payload.bytes)
    except ModelNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Prediction failed: {exc}",
        ) from exc
