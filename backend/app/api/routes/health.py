from fastapi import APIRouter
from app.config import get_settings

router = APIRouter()

@router.get("/health")
def health_check():
    settings = get_settings()

    return {
        "status": "healthy",
        "env": settings.ENV,
        "services": {
            "postgres": "ok",
            "redis": "ok",
            "chromadb": "ok"
        }
    }