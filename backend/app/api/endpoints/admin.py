from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException, status

from app.core.dependencies import require_admin
from app.core.security import hash_password
from app.models.user import UserRole
from app.repositories.users import create_user, delete_user, find_user_by_email, find_user_by_user_id, list_analyst_activity
from app.schemas.admin import AddAnalystResponse, AnalystCreate
from app.services.email_notifications import send_onboarding_email

router = APIRouter(prefix="/admin", tags=["admin"])


def build_user_id(name: str, email: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "", (name or email.split("@", 1)[0]).lower())
    return base[:24] or "analyst"


async def _unique_user_id(name: str, email: str) -> str:
    base = build_user_id(name, email)
    candidate = base
    suffix = 1
    while await find_user_by_user_id(candidate):
        candidate = f"{base}{suffix}"
        suffix += 1
    return candidate


@router.post("/add-analyst", response_model=AddAnalystResponse)
async def add_analyst(
    payload: AnalystCreate,
    _: dict = Depends(require_admin),
):
    if payload.role.lower() != UserRole.analyst.value:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Only analyst accounts can be created here")

    existing = await find_user_by_email(payload.email)
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="An account with this email already exists")

    display_name = (payload.name or payload.full_name or payload.username or "").strip()
    if not display_name:
        display_name = payload.email.split("@", 1)[0]

    user_id = await _unique_user_id(display_name, payload.email)

    password_hash = hash_password(payload.password)
    analyst = await create_user(
        user_id=user_id,
        role=UserRole.analyst,
        password_hash=password_hash,
        email=payload.email,
        name=display_name,
        provider="password",
    )

    send_onboarding_email(analyst["email"], payload.password)

    return AddAnalystResponse(
        message="Analyst created successfully",
        user_id=user_id,
        email=payload.email,
    )


@router.get("/analyst-activity")
async def analyst_activity(_: dict = Depends(require_admin)):
    return {"records": await list_analyst_activity()}


@router.delete("/delete-analyst/{analyst_id}")
async def delete_analyst(analyst_id: str, _: dict = Depends(require_admin)):
    analyst = await find_user_by_user_id(analyst_id)
    if not analyst or analyst.get("role") != UserRole.analyst.value:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analyst not found")

    deleted = await delete_user(analyst_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analyst not found")

    return {"message": "Analyst deleted successfully", "user_id": analyst_id}
