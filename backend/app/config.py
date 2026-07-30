import os
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict

# Chemin absolu vers la racine du projet (backend/app/config.py -> remonte 2 niveaux -> racine)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ENV_PATH = os.path.join(BASE_DIR, ".env")

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
    
    # === EMAIL (réinitialisation mot de passe) ===
    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = ""
    FRONTEND_URL: str = "http://localhost:5173"
    # === APP ===
    ENV: str = "dev"

    class Config:
        env_file = ENV_PATH
        extra = "ignore"

ORG_DOMAINS = ["star.com.tn", "staragence.com.tn"]


def is_org_domain(domain: str) -> bool:
    domain = domain.lower().strip()
    return any(domain == d or domain.endswith(f".{d}") for d in ORG_DOMAINS)


@lru_cache()
def get_settings():
    return Settings()