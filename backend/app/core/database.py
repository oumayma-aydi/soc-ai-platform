from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from app.config import get_settings

settings = get_settings()

# On utilise POSTGRES_URL depuis config.py (qui lit ton .env)
engine = create_engine(
    settings.POSTGRES_URL,
    echo=False,          # Mettre True si tu veux voir les requêtes SQL dans le terminal (debug)
    pool_pre_ping=True   # Vérifie que la connexion est vivante avant chaque requête
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    """
    Dependency FastAPI : injecte une session DB dans chaque route qui en a besoin.
    Le 'finally' garantit que la session est toujours fermée même si une erreur survient.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
