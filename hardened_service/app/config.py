import os
from functools import lru_cache
from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    SECRET_KEY: str = Field(default="change-me")
    MAX_UPLOAD_SIZE: int = Field(default=5 * 1024 * 1024)
    ALLOWED_EXTENSIONS: str = Field(default="png,jpg,jpeg,pdf")
    TOKEN_EXP_SECONDS: int = Field(default=300)
    CLAMD_HOST: str = Field(default="", validation_alias=AliasChoices("CLAMD_HOST", "CLAMAV_HOST"))
    CLAMD_PORT: int = Field(default=3310, validation_alias=AliasChoices("CLAMD_PORT", "CLAMAV_PORT"))
    RATE_LIMIT_REQUESTS: int = Field(default=20)
    RATE_LIMIT_WINDOW_SECONDS: int = Field(default=60)
    LOG_LEVEL: str = Field(default="INFO")

    model_config = {"env_file": ".env", "case_sensitive": False}

    def clamav_enabled(self) -> bool:
        return bool(self.CLAMD_HOST and self.CLAMD_HOST.strip())

    def allowed_extensions_list(self) -> list[str]:
        return [ext.strip().lower() for ext in self.ALLOWED_EXTENSIONS.split(",") if ext.strip()]

    def model_dump(self, *args, **kwargs):
        d = super().model_dump(*args, **kwargs)
        d["SECRET_KEY"] = "***redacted***" if d.get("SECRET_KEY") else None
        return d


@lru_cache()
def get_settings() -> Settings:
    return Settings()


