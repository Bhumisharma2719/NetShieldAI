from datetime import datetime, timezone
from typing import Any

from sqlalchemy import text

from app.db.postgres import get_sessionmaker
from app.models.user import UserRole


def row_to_dict(row: Any) -> dict[str, Any] | None:
    return dict(row._mapping) if row else None


async def find_user_by_user_id(user_id: str) -> dict[str, Any] | None:
    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session:
        result = await session.execute(text("SELECT * FROM users WHERE user_id = :user_id"), {"user_id": user_id})
        return row_to_dict(result.first())


async def find_user_by_email(email: str) -> dict[str, Any] | None:
    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session:
        result = await session.execute(text("SELECT * FROM users WHERE email = :email"), {"email": email.lower()})
        return row_to_dict(result.first())


async def create_user(
    user_id: str,
    role: UserRole,
    password_hash: str | None = None,
    email: str | None = None,
    name: str | None = None,
    provider: str = "password",
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    document = {
        "user_id": user_id,
        "role": role.value,
        "password_hash": password_hash,
        "email": email.lower() if email else None,
        "name": name,
        "provider": provider,
        "created_at": now,
        "updated_at": now,
        "is_active": True,
    }

    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session:
        await session.execute(
            text(
                """
                INSERT INTO users (
                    user_id, role, password_hash, email, name, provider, created_at, updated_at, is_active
                )
                VALUES (
                    :user_id, :role, :password_hash, :email, :name, :provider, :created_at, :updated_at, :is_active
                )
                """
            ),
            document,
        )
        await session.commit()

    return document


async def update_user_profile(user_id: str, email: str | None = None, name: str | None = None) -> None:
    updates: dict[str, Any] = {"updated_at": datetime.now(timezone.utc)}
    if email:
        updates["email"] = email.lower()
    if name:
        updates["name"] = name

    assignments = ", ".join(f"{field} = :{field}" for field in updates)
    updates["user_id"] = user_id

    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session:
        await session.execute(text(f"UPDATE users SET {assignments} WHERE user_id = :user_id"), updates)
        await session.commit()
