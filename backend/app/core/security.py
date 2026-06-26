from datetime import datetime, timedelta, timezone
import bcrypt
from jose import jwt, JWTError
from app.config import get_settings
import re
from fastapi import HTTPException, status

settings = get_settings()


def hash_password(plain_password: str) -> str:
    """Transforme un mot de passe en clair en hash bcrypt irréversible."""
    password_bytes = plain_password.encode("utf-8")
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Compare un mot de passe en clair avec son hash stocké en base."""
    return bcrypt.checkpw(
        plain_password.encode("utf-8"),
        hashed_password.encode("utf-8")
    )


def create_access_token(data: dict) -> str:
    """Crée un JWT access_token de courte durée (ACCESS_TOKEN_EXPIRE_MINUTES)."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def create_refresh_token(data: dict) -> str:
    """Crée un JWT refresh_token de longue durée (7 jours)."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=7)
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    """Décode et vérifie un JWT. Lève une JWTError si invalide ou expiré."""
    return jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])

def validate_password_strength(password: str):
    """
    Vérifie les critères de complexité de l'ANSSI.
    """
    if len(password) < 12:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Le mot de passe doit contenir au moins 12 caractères."
        )
    if not re.search(r"[A-Z]", password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Le mot de passe doit contenir au moins une majuscule."
        )
    if not re.search(r"[a-z]", password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Le mot de passe doit contenir au moins une minuscule."
        )
    if not re.search(r"[0-9]", password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Le mot de passe doit contenir au moins un chiffre."
        )
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>_+-]", password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Le mot de passe doit contenir au moins un caractère spécial."
        )
