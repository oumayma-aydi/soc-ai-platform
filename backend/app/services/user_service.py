import uuid
from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from datetime import datetime, timezone, timedelta
import secrets
import hashlib

from app.models.orm import UserORM, UserPasswordHistoryORM, PasswordResetRequestORM
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

MAX_FAILED_ATTEMPTS = 3  # au lieu de 5


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

    if datetime.now(timezone.utc) > user.password_updated_at.replace(tzinfo=timezone.utc) + timedelta(days=60):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Votre mot de passe a expiré (60 jours). Vous devez le renouveler."
        )

    if not verify_password(password, user.hashed_password):
        user.failed_login_attempts += 1

        if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
            user.is_active = 0
            db.commit()

            # Notifier tous les admins du blocage — sauf si c'est l'admin lui-même qui est bloqué,
            # auquel cas on le notifie directement (c'est le seul admin, il doit savoir).
            from app.services.email_service import notify_admins_account_locked
            admin_emails = [u.email for u in db.query(UserORM).filter(UserORM.role == "admin").all()]
            if admin_emails:
                try:
                    notify_admins_account_locked(admin_emails, user.username, user.role)
                except Exception:
                    # L'échec d'envoi d'e-mail ne doit jamais empêcher le blocage de sécurité de s'appliquer
                    pass

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Compte bloqué. Trop de tentatives infructueuses (limite: {MAX_FAILED_ATTEMPTS})."
            )

        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Identifiants incorrects")

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

def _hash_reset_token(raw_token: str) -> str:
    """Le token brut part par e-mail ; seul son hash SHA-256 est stocké en base."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def get_user_by_username_or_email(db: Session, identifier: str) -> UserORM | None:
    return db.query(UserORM).filter(
        (UserORM.username == identifier) | (UserORM.email == identifier)
    ).first()


def initiate_password_reset(db: Session, identifier: str) -> None:
    """
    Point d'entrée unique pour les deux rôles. Ne lève jamais d'exception
    métier visible côté client (anti-énumération de comptes) : l'appelant
    HTTP renvoie toujours la même réponse générique quel que soit le résultat.
    """
    user = get_user_by_username_or_email(db, identifier)
    if not user:
        return  # silencieux — ne révèle pas si le compte existe

    from app.services.email_service import send_admin_self_reset_link, notify_admins_reset_request

    if user.role == "admin":
        raw_token = secrets.token_urlsafe(32)
        user.reset_token_hash = _hash_reset_token(raw_token)
        user.reset_token_expires_at = datetime.now(timezone.utc) + timedelta(minutes=30)
        db.commit()

        from app.config import get_settings
        settings = get_settings()
        reset_link = f"{settings.FRONTEND_URL}/reset-password?token={raw_token}"
        send_admin_self_reset_link(user.email, reset_link)
    else:
        pending = PasswordResetRequestORM(user_id=user.id)
        db.add(pending)
        db.commit()

        admin_emails = [u.email for u in db.query(UserORM).filter(UserORM.role == "admin").all()]
        if admin_emails:
            notify_admins_reset_request(admin_emails, user.username, user.role)


def reset_password_with_token(db: Session, raw_token: str, new_password: str) -> None:
    """Auto-service admin uniquement — appelé depuis le lien reçu par e-mail."""
    token_hash = _hash_reset_token(raw_token)
    user = db.query(UserORM).filter(UserORM.reset_token_hash == token_hash).first()

    if not user or not user.reset_token_expires_at:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Lien de réinitialisation invalide.")

    if datetime.now(timezone.utc) > user.reset_token_expires_at.replace(tzinfo=timezone.utc):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Ce lien de réinitialisation a expiré.")

    validate_password_strength(new_password)

    history_entry = UserPasswordHistoryORM(user_id=user.id, hashed_password=user.hashed_password)
    db.add(history_entry)

    user.hashed_password = hash_password(new_password)
    user.password_updated_at = datetime.now(timezone.utc)
    user.reset_token_hash = None
    user.reset_token_expires_at = None
    user.failed_login_attempts = 0
    user.is_active = 1
    db.commit()


def admin_set_user_password(db: Session, target_user: UserORM, new_password: str, admin_username: str) -> None:
    """L'admin définit lui-même un nouveau mot de passe pour un analyst/auditor."""
    validate_password_strength(new_password)

    history_entry = UserPasswordHistoryORM(user_id=target_user.id, hashed_password=target_user.hashed_password)
    db.add(history_entry)

    target_user.hashed_password = hash_password(new_password)
    target_user.password_updated_at = datetime.now(timezone.utc)
    target_user.failed_login_attempts = 0
    target_user.is_active = 1
    db.commit()

    db.query(PasswordResetRequestORM).filter(
        PasswordResetRequestORM.user_id == target_user.id,
        PasswordResetRequestORM.resolved == 0
    ).update({"resolved": 1, "resolved_at": datetime.now(timezone.utc), "resolved_by": admin_username})
    db.commit()
    
def count_admins(db: Session) -> int:
    return db.query(UserORM).filter(UserORM.role == "admin").count()


def create_user(db: Session, username: str, email: str, password: str, role: str) -> UserORM:
    """Crée un nouvel utilisateur avec mot de passe hashé après validation de force."""
    validate_password_strength(password)

    if get_user_by_username(db, username):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Le nom d'utilisateur '{username}' existe déjà"
        )

    # Un seul compte admin autorisé dans le système
    if role == "admin" and count_admins(db) >= 1:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Un compte administrateur existe déjà. Un seul admin est autorisé sur la plateforme."
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

def verify_admin_password(db: Session, admin: UserORM, password: str) -> None:
    """Revérifie le mot de passe de l'admin avant une action sensible
    (changement de rôle, réinitialisation de mot de passe, suppression de compte)."""
    if not verify_password(password, admin.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Mot de passe incorrect. Action annulée."
        )