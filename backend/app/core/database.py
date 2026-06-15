import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# URL de connexion PostgreSQL (à adapter avec tes identifiants locaux ou variables d'environnement)
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:password@localhost:5432/soc_ai_db")

engine = create_engine(DATABASE_URL, echo=False)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    """Dependency pour injecter la session de BDD dans l'API FastAPI"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()