from app.core.config import settings
from app.core.security import hash_password
from app.models.user import UserRole
from app.repositories.users import create_user, find_user_by_user_id, update_user_profile


async def seed_default_users() -> None:
    defaults = [
        (
            settings.default_admin_user_id,
            settings.default_admin_password,
            UserRole.admin,
            settings.google_admin_email.strip().lower() or None,
        ),
        (
            settings.default_analyst_user_id,
            settings.default_analyst_password,
            UserRole.analyst,
            settings.analyst_email_list[0] if settings.analyst_email_list else None,
        ),
    ]

    for user_id, password, role, email in defaults:
        existing_user = await find_user_by_user_id(user_id)
        if existing_user is None:
            await create_user(user_id=user_id, password_hash=hash_password(password), role=role, email=email)
        elif email and existing_user.get("email") != email:
            await update_user_profile(user_id=user_id, email=email)

    for email in settings.analyst_email_list[1:]:
        user_id = email.split("@")[0].lower()
        existing_user = await find_user_by_user_id(user_id)
        if existing_user is None:
            await create_user(user_id=user_id, role=UserRole.analyst, email=email, provider="google")
