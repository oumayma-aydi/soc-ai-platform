from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.endpoints import incidents
from app.api.routes import health, auth

#  Magie SQLAlchemy : Crée automatiquement les nouvelles tables/colonnes manquantes
from app.core.database import engine, Base
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Star Assurance — AI-Powered SOC Platform",
    description="API Gateway d'analyse d'incidents cyber augmentée par IA Multi-Agents",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router, prefix="/api", tags=["Sante Cluster"])
app.include_router(auth.router, prefix="/api/auth", tags=["Authentification"])
app.include_router(incidents.router, prefix="/api/incidents", tags=["Incidents"])
