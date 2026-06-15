from sqlalchemy import Column, String, Integer, Float, DateTime, JSON
from sqlalchemy.dialects.postgresql import JSONB
from app.core.database import Base
import datetime

class IncidentORM(Base):
    """Représentation de la table 'incidents' dans PostgreSQL"""
    __tablename__ = "incidents"

    id = Column(String, primary_key=True, index=True) # Ex: INC-2026-001
    raw_log = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    
    # Données issues de la classification et de l'enrichissement
    incident_type = Column(String, nullable=True)
    severity = Column(Integer, nullable=True)
    urgency = Column(String, nullable=True)
    
    # Stockage structuré sous forme de JSONB (Spécifique Postgres, ultra rapide)
    iocs = Column(JSONB, default=[])
    mitre_techniques = Column(JSONB, default=[])
    kill_chain = Column(JSONB, default=[])
    remediation = Column(JSONB, default={})
    
    # Notre fameux score métrique
    confidence_score = Column(Float, nullable=True)