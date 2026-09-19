from typing import List, Union
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )

    # Project Information
    PROJECT_NAME: str = "AI-Powered Autonomous Cybersecurity & Incident Investigation Platform"
    VERSION: str = "0.1.0"
    API_V1_STR: str = "/api/v1"

    # PostgreSQL & Database Configuration
    POSTGRES_DB: str = "cyber_soc_db"
    POSTGRES_USER: str = "soc_admin"
    POSTGRES_PASSWORD: str = "soc_secure_pass_123"
    DATABASE_URL: str = "sqlite+aiosqlite:///./test_soc.db"

    # JWT Authentication & Cryptography
    JWT_SECRET_KEY: str = "default_insecure_development_secret_key_minimum_32_chars"
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # CORS & Network Boundaries
    CORS_ORIGINS: Union[str, List[str]] = "http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173"

    # Initial Security Admin Bootstrap Credentials
    BOOTSTRAP_ADMIN_USERNAME: str = "admin"
    BOOTSTRAP_ADMIN_PASSWORD: str = "AdminSecurePass123!"

    # Security & Protection Limits
    MAX_REQUEST_SIZE_BYTES: int = 10 * 1024 * 1024  # 10 Megabytes
    RATE_LIMIT_REQUESTS_PER_MINUTE: int = 120

    # Generative AI Security Copilot Settings (Modular & Provider-Independent)
    LLM_PROVIDER: str = "auto"  # 'auto', 'gemini', 'openai', 'custom', or 'local_deterministic'
    LLM_API_KEY: Union[str, None] = None
    LLM_API_URL: Union[str, None] = None
    LLM_MODEL: str = "gemini-1.5-pro"

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            return [i.strip() for i in v.split(",") if i.strip()]
        return v

    @property
    def async_database_url(self) -> str:
        url = self.DATABASE_URL
        # If postgresql:// is provided, normalize to postgresql+asyncpg://
        if url.startswith("postgresql://"):
            url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
        elif url.startswith("postgres://"):
            url = url.replace("postgres://", "postgresql+asyncpg://", 1)
        return url


settings = Settings()
