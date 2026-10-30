"""Configuration management for SENTINEL X backend using Pydantic Settings."""

import os
from typing import List, Union
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables and .env file."""

    ENVIRONMENT: str = Field(default="development", description="Environment: development, staging, production")
    DEBUG: bool = Field(default=False, description="Debug mode flag")
    APP_NAME: str = Field(default="SENTINEL_X_BACKEND", description="Application name")
    API_V1_PREFIX: str = Field(default="/api/v1", description="API version 1 prefix")

    # Allowed CORS Origins
    ALLOWED_ORIGINS: Union[str, List[str]] = Field(
        default="http://localhost:3000,http://localhost:5173,http://127.0.0.1:5500,http://localhost:8000",
        description="Allowed CORS origins as comma-separated string or list",
    )

    # Firebase Settings
    FIREBASE_PROJECT_ID: str = Field(default="sentinel-x-demo", description="Firebase project ID")
    FIREBASE_CREDENTIALS_PATH: str = Field(
        default="serviceAccountKey.json",
        description="Path to service account JSON file",
    )
    FIREBASE_USE_EMULATOR: bool = Field(default=False, description="Use Firebase local emulator")
    FIRESTORE_EMULATOR_HOST: str = Field(default="localhost:8080", description="Firestore emulator host")
    FIREBASE_AUTH_EMULATOR_HOST: str = Field(default="localhost:9099", description="Firebase Auth emulator host")

    # Cryptography
    SENTINEL_MASTER_KEY: str = Field(
        default="k8qY3mR1wH2bV9tL7oP5xJ0nU4zF6gC8eD1sA3vK5yI=",
        description="Base64-encoded 32-byte master encryption key",
    )

    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = Field(default=60, description="Max requests per minute per IP")

    # Request Size Limit (e.g., 2 MB)
    MAX_REQUEST_SIZE_BYTES: int = Field(default=2 * 1024 * 1024, description="Max request body size in bytes")

    # Optional Threat Intelligence
    THREAT_INTEL_API_KEY: str = Field(default="", description="Optional external threat intel API key")
    THREAT_INTEL_PROVIDER: str = Field(default="", description="Optional threat intel provider name")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @field_validator("ALLOWED_ORIGINS", mode="before")
    @classmethod
    def parse_allowed_origins(cls, value: Union[str, List[str]]) -> List[str]:
        if isinstance(value, str):
            origins = [o.strip() for o in value.split(",") if o.strip()]
            return origins
        return value

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT.lower() == "production"


# Singleton instance
settings = Settings()
