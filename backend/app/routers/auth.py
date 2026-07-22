from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from google.auth.exceptions import GoogleAuthError
from google.auth.transport import requests
from google.oauth2 import id_token

from app.core.config import settings
from app.core.security import create_access_token, decode_access_token, verify_password
from app.models.user import UserRole
from app.repositories.users import find_user_by_email, find_user_by_user_id
from app.schemas.auth import GoogleLoginRequest, LoginRequest, TokenResponse, UserResponse

router = APIRouter(prefix="/auth", tags=["auth"])
bearer_scheme = HTTPBearer()


def build_token_response(user: dict) -> TokenResponse:
    public_user = UserResponse(
        user_id=user["user_id"],
        role=UserRole(user["role"]),
        email=user.get("email"),
        name=user.get("name"),
    )
    token = create_access_token(
        subject=user["user_id"],
        claims={"role": public_user.role.value, "email": public_user.email, "name": public_user.name},
    )
    return TokenResponse(access_token=token, user=public_user)


@router.post("/login", response_model=TokenResponse)
async def login(payload: LoginRequest):
    user = await find_user_by_user_id(payload.user_id)
    if not user or not user.get("is_active"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid user ID or password")

    password_hash = user.get("password_hash")
    if not password_hash or not verify_password(payload.password, password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid user ID or password")

    return build_token_response(user)


@router.post("/google", response_model=TokenResponse)
async def google_login(payload: GoogleLoginRequest):
    if not settings.google_client_id_list:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Google login is not configured")

    last_error: ValueError | None = None
    try:
        verified = None
        for client_id in settings.google_client_id_list:
            try:
                verified = id_token.verify_oauth2_token(payload.credential, requests.Request(), client_id)
                break
            except ValueError as exc:
                last_error = exc
        if verified is None:
            raise last_error or ValueError("Invalid Google credential")
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=(
                "Invalid Google credential. "
                f"Google verifier said: {str(exc) or 'unknown verification error'}"
            ),
        ) from exc
    except GoogleAuthError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Google verification service is not reachable. Check backend internet access.",
        ) from exc

    email = verified.get("email", "").lower()
    if not email:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Google account has no email")
    if verified.get("email_verified") is not True:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Google email is not verified")

    user = await find_user_by_email(email)
    if user is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="This Google email is not registered")

    return build_token_response(user)


@router.get("/me", response_model=UserResponse)
async def me(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    try:
        payload = decode_access_token(credentials.credentials)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from exc

    user = await find_user_by_user_id(payload["sub"])
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User no longer exists")

    return UserResponse(
        user_id=user["user_id"],
        role=UserRole(user["role"]),
        email=user.get("email"),
        name=user.get("name"),
    )
