from functools import lru_cache
from pathlib import Path

from pydantic import computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=BACKEND_DIR / ".env", env_file_encoding="utf-8")

    app_name: str = "NetShield AI API"
    environment: str = "development"
    api_prefix: str = "/api"
    port: int = 8000

    database_url: str = ""
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_user: str = "postgres"
    postgres_password: str = "postgres"
    postgres_db: str = "netshield_ai"

    jwt_secret_key: str = "change-this-secret-key"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 1440

    backend_cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    google_client_id: str = ""
    google_admin_email: str = ""
    google_analyst_emails: str = ""
    sniffer_iface: str = ""

    smtp_server: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_use_tls: bool = True
    smtp_from_email: str = ""

    seed_default_users: bool = True
    default_admin_user_id: str = "admin"
    default_admin_password: str = "admin123"
    default_analyst_user_id: str = "analyst"
    default_analyst_password: str = "analyst123"

    @computed_field
    @property
    def cors_origins(self) -> list[str]:
        return [origin.strip() for origin in self.backend_cors_origins.split(",") if origin.strip()]

    @computed_field
    @property
    def analyst_email_list(self) -> list[str]:
        return [email.strip().lower() for email in self.google_analyst_emails.split(",") if email.strip()]

    @computed_field
    @property
    def google_client_id_list(self) -> list[str]:
        return [client_id.strip() for client_id in self.google_client_id.split(",") if client_id.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
