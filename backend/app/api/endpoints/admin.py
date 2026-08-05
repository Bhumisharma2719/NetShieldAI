from __future__ import annotations

import re

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status

from app.core.dependencies import require_admin
from app.core.security import hash_password
from app.models.user import UserRole
from app.repositories.users import create_user, find_user_by_email, find_user_by_user_id, list_analyst_activity
from app.schemas.admin import AddAnalystRequest, AddAnalystResponse
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
    payload: AddAnalystRequest,
    background_tasks: BackgroundTasks,
    _: dict = Depends(require_admin),
):
    if payload.role.lower() != UserRole.analyst.value:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Only analyst accounts can be created here")

    existing = await find_user_by_email(payload.email)
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="An account with this email already exists")

    user_id = payload.user_id.strip() if payload.user_id else await _unique_user_id(payload.name, payload.email)
    if await find_user_by_user_id(user_id):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="This user ID already exists")

    password_hash = hash_password(payload.password)
    await create_user(
        user_id=user_id,
        role=UserRole.analyst,
        password_hash=password_hash,
        email=payload.email,
        name=payload.name,
        provider="password",
    )

    background_tasks.add_task(
        send_onboarding_email,
        to_email=payload.email,
        name=payload.name,
        user_id=user_id,
        password=payload.password,
    )

    return AddAnalystResponse(
        message="Analyst created successfully",
        user_id=user_id,
        email=payload.email,
    )


@router.get("/analyst-activity")
async def analyst_activity(_: dict = Depends(require_admin)):
    return {"records": await list_analyst_activity()}
