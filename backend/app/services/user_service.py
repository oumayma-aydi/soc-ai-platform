import uuid
from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from datetime import datetime, timezone, timedelta

from app.models.orm import UserORM, UserPasswordHistoryORM
from app.core.security import hash_password, verify_password, validate_password_strength

def generate_user_id() -> str:
    """Génère un ID unique style USR-XXXXXXXX."""
    return f"USR-{uuid.uuid4().hex[:8].upper()}"

def get_user_by_username(db: Session, username: str) -> UserORM | None:
    return db.query(UserORM).filter(UserORM.username == username).first()

def create_user(db: Session, username: str, email: str, password: str, role: str) -> UserORM:
    """Crée un nouvel utilisateur avec mot de passe hashé après validation de force."""
    # 1. Validation de la complexité ANSSI
    validate_password_strength(password)
    
    # 2. Vérification d'unicité
    if get_user_by_username(db, username):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Le nom d'utilisateur '{username}' existe déjà"
        )

    user = UserORM(
        id=generate_user_id(),
        username=username,
        email=email,
        hashed_password=hash_password(password),
        role=role,
        is_active=1
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

def authenticate_user(db: Session, username: str, password: str) -> UserORM:
    """Authentifie l'utilisateur, gère l'expiration temporelle et le blocage anti-bruteforce."""
    user = db.query(UserORM).filter(UserORM.username == username).first()
    
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Identifiants incorrects")
        
    if user.is_active == 0:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Compte bloqué suite à trop de tentatives. Contactez l'administrateur."
        )

    # Vérification de la validité du mot de passe (60 jours)
    if datetime.now(timezone.utc) > user.password_updated_at.replace(tzinfo=timezone.utc) + timedelta(days=60):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Votre mot de passe a expiré (60 jours). Vous devez le renouveler."
        )

    if not verify_password(password, user.hashed_password):
        # Échec : On incrémente le compteur de fautes
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= 5:
            user.is_active = 0  # Blocage automatique instantané
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, 
                detail="Compte bloqué. Trop de tentatives infructueuses (limite: 5)."
            )
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Identifiants incorrects")

    # Succès : On reset le compteur à zéro
    user.failed_login_attempts = 0
    db.commit()
    return user

def change_user_password(db: Session, user: UserORM, new_password: str):
    """Change le mot de passe en vérifiant la non-réutilisation des 5 derniers pass."""
    # 1. Valider la complexité
    validate_password_strength(new_password)
    
    # 2. Vérifier l'historique des 5 derniers mots de passe
    for old_pass in user.password_history[-5:]:
        if verify_password(new_password, old_pass.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Interdit : Vous ne pouvez pas réutiliser vos 5 derniers mots de passe."
            )
            
    # 3. Archiver l'ancien mot de passe
    history_entry = UserPasswordHistoryORM(user_id=user.id, hashed_password=user.hashed_password)
    db.add(history_entry)
    
    # 4. Mettre à jour le nouveau
    user.hashed_password = hash_password(new_password)
    user.password_updated_at = datetime.now(timezone.utc)
    db.commit()
