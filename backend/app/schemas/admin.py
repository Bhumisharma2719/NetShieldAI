from pydantic import BaseModel, EmailStr, Field


class AnalystCreate(BaseModel):
    full_name: str | None = Field(default=None, min_length=2, max_length=255)
    username: str | None = Field(default=None, min_length=2, max_length=120)
    name: str | None = Field(default=None, min_length=2, max_length=255)
    email: EmailStr
    password: str = Field(..., min_length=6, max_length=128)
    role: str = Field(default="analyst", min_length=3, max_length=32)


class AddAnalystResponse(BaseModel):
    message: str
    user_id: str
    email: EmailStr


class AnalystActivityResponse(BaseModel):
    user_id: str
    name: str | None = None
    email: EmailStr | None = None
    role: str
    provider: str
    is_active: bool
    created_at: str
    updated_at: str
    last_login_at: str | None = None
