import os
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # === API KEYS ===
    GROQ_API_KEY: str
    VIRUSTOTAL_API_KEY: str
    ABUSEIPDB_API_KEY: str
    OTX_API_KEY: str

    # === DATABASE ===
    POSTGRES_URL: str = "postgresql://socuser:socpassword@postgres:5432/socdb"
    REDIS_URL: str = "redis://redis:6379/0"
    CHROMA_URL: str = "http://chromadb:8000"

    # === SECURITY ===
    JWT_SECRET: str
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # === APP ===
    ENV: str = "dev"

    class Config:
        env_file = ".env"
        extra = "ignore"


@lru_cache()
def get_settings():
    return Settings()