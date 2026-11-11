from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Validated runtime configuration loaded from environment variables."""

    app_name: str = "AegisSOC API"
    app_env: Literal["development", "test", "staging", "production"] = "development"
    database_url: str = "sqlite:///./aegissoc.db"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    auth_secret_key: str = "dev-only-change-this-aegissoc-secret-key"
    access_token_minutes: int = Field(default=30, ge=5, le=1440)
    oidc_enabled: bool = False
    oidc_issuer_url: str | None = None
    oidc_client_id: str | None = None
    oidc_client_secret: str | None = None
    oidc_redirect_url: str | None = None
    oidc_scopes: str = "openid profile email"

    @model_validator(mode="after")
    def validate_security_settings(self):
        if self.app_env == "production":
            if len(self.auth_secret_key) < 32 or self.auth_secret_key == "dev-only-change-this-aegissoc-secret-key":
                raise ValueError("Production requires a unique AUTH_SECRET_KEY of at least 32 characters")
        if self.oidc_enabled:
            required = (self.oidc_issuer_url, self.oidc_client_id, self.oidc_client_secret, self.oidc_redirect_url)
            if not all(required):
                raise ValueError("OIDC requires issuer, client ID, client secret, and redirect URL")
            if not self.oidc_issuer_url.startswith("https://"):
                raise ValueError("OIDC issuer URL must use HTTPS")
            if not self.oidc_redirect_url.startswith("https://") and not (
                self.app_env == "development" and self.oidc_redirect_url.startswith("http://localhost")
            ):
                raise ValueError("OIDC redirect URL must use HTTPS (localhost is allowed in development)")
        return self

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        validate_default=True,
    )


settings = Settings()
