from pydantic import BaseModel, EmailStr, Field

from app.models.user import UserRole


class LoginRequest(BaseModel):
    user_id: str = Field(..., min_length=2)
    password: str = Field(..., min_length=6)


class GoogleLoginRequest(BaseModel):
    credential: str = Field(..., min_length=10)


class UserResponse(BaseModel):
    user_id: str
    role: UserRole
    email: EmailStr | None = None
    name: str | None = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse
