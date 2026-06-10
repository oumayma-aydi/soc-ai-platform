from fastapi import FastAPI
from app.api.routes.health import router as health_router

app = FastAPI(
    title="SOC AI Platform",
    description="Multi-agent SOC augmentation system",
    version="0.1.0"
)

# Routes
app.include_router(health_router, prefix="/api")

@app.get("/")
def root():
    return {
        "message": "SOC AI Platform API running",
        "status": "ok"
    }