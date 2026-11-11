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

    @model_validator(mode="after")
    def validate_security_settings(self):
        if self.app_env == "production":
            if len(self.auth_secret_key) < 32 or self.auth_secret_key == "dev-only-change-this-aegissoc-secret-key":
                raise ValueError("Production requires a unique AUTH_SECRET_KEY of at least 32 characters")
        return self

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        validate_default=True,
    )


settings = Settings()
