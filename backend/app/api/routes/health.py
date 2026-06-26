from fastapi import APIRouter, Response
from app.config import get_settings
from app.core.database import engine
from sqlalchemy import text
import redis
import chromadb
from urllib.parse import urlparse

router = APIRouter()


@router.get("/health")
def health_check(response: Response):
    settings = get_settings()
    services = {}
    all_healthy = True

    # --- Test PostgreSQL ---
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        services["postgres"] = "ok"
    except Exception as e:
        services["postgres"] = f"error: {str(e)}"
        all_healthy = False

    # --- Test Redis ---
    try:
        parsed_redis = urlparse(settings.REDIS_URL)
        r = redis.Redis(host=parsed_redis.hostname, port=parsed_redis.port, socket_timeout=3)
        r.ping()
        services["redis"] = "ok"
    except Exception as e:
        services["redis"] = f"error: {str(e)}"
        all_healthy = False

    # --- Test ChromaDB ---
    try:
        parsed_chroma = urlparse(settings.CHROMA_URL)
        client = chromadb.HttpClient(host=parsed_chroma.hostname, port=parsed_chroma.port)
        client.heartbeat()
        services["chromadb"] = "ok"
    except Exception as e:
        services["chromadb"] = f"error: {str(e)}"
        all_healthy = False

    # Si un service échoue, on retourne 503 pour que Kubernetes sache que le pod n'est pas prêt
    if not all_healthy:
        response.status_code = 503

    return {
        "status": "healthy" if all_healthy else "degraded",
        "env": settings.ENV,
        "services": services
    }
