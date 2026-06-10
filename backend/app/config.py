from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    # === API KEYS ===
    GROQ_API_KEY: str
    VIRUSTOTAL_API_KEY: str
    ABUSEIPDB_API_KEY: str
    OTX_API_KEY: str

    # === DATABASE ===
    POSTGRES_URL: str = "postgresql://postgres:postgres@localhost:5432/socdb"
    REDIS_URL: str = "redis://localhost:6379"
    CHROMA_URL: str = "http://localhost:8001"

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