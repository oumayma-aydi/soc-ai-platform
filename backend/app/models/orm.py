from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from app.core.database import Base

class UserORM(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="analyst")
    is_active = Column(Integer, default=1)  # 1 = Actif, 0 = Bloqué
    
    # Politique de sécurité
    failed_login_attempts = Column(Integer, default=0)
    password_updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    
    reset_token_hash = Column(String, nullable=True)
    reset_token_expires_at = Column(DateTime, nullable=True)
    
    # Relation avec l'historique
    password_history = relationship("UserPasswordHistoryORM", back_populates="user", cascade="all, delete-orphan")


class UserPasswordHistoryORM(Base):
    __tablename__ = "user_password_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    hashed_password = Column(String, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    user = relationship("UserORM", back_populates="password_history")


class IncidentORM(Base):
    __tablename__ = "incidents"

    id = Column(String, primary_key=True, index=True)
    incident_type = Column(String, nullable=False)
    severity = Column(Integer, nullable=False)
    confidence_score = Column(Integer, nullable=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    raw_log = Column(String, nullable=False)
    
    mitre_techniques = Column(JSON, default=[])
    remediation = Column(JSON, default={}) # aligné sur ton backend
    kill_chain = Column(JSON, default=[])
    iocs = Column(JSON, default=[])
    
    # --- NOUVELLES COLONNES POUR L'ENRICHISSEMENT GÉO ---
    source_ip = Column(String, nullable=True)
    geo_data = Column(JSON, default={})

class PasswordResetRequestORM(Base):
    """Demande de réinitialisation pour un compte analyst/auditor,
    à traiter manuellement par un admin."""
    __tablename__ = "password_reset_requests"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    requested_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    resolved = Column(Integer, default=0)  # 0 = en attente, 1 = traité
    resolved_at = Column(DateTime, nullable=True)
    resolved_by = Column(String, nullable=True)  # username de l'admin qui a traité

    user = relationship("UserORM")