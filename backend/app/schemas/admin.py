from pydantic import BaseModel, EmailStr, Field, model_validator


class AddAnalystRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=255)
    email: EmailStr
    role: str = Field(default="analyst", min_length=3, max_length=32)
    password: str = Field(..., min_length=6, max_length=128)
    user_id: str | None = Field(default=None, min_length=2, max_length=120)

    @model_validator(mode="before")
    @classmethod
    def normalize_payload(cls, value):
        if not isinstance(value, dict):
            return value

        normalized = dict(value)
        if not normalized.get("name") and normalized.get("full_name"):
            normalized["name"] = normalized["full_name"]

        if not normalized.get("role"):
            normalized["role"] = "analyst"

        return normalized


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
