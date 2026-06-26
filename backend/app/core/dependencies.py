from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from jose import JWTError

from app.core.database import get_db
from app.core.security import decode_token
from app.models.orm import UserORM

# Indique à Swagger/FastAPI où se trouve la route de login (pour le bouton "Authorize")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

# Rôles valides dans le système — source unique de vérité
VALID_ROLES = {"admin", "analyst", "auditor"}


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> UserORM:
    """
    Dependency réutilisable : extrait le token du header Authorization,
    le décode, et retourne l'utilisateur correspondant en base.
    Lève une 401 si le token est invalide, expiré, ou si l'utilisateur n'existe plus.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token invalide ou expiré",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = decode_token(token)
        if payload.get("type") != "access":
            raise credentials_exception
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(UserORM).filter(UserORM.username == username).first()
    if user is None or user.is_active != 1:
        raise credentials_exception

    return user


def require_roles(*allowed_roles: str):
    """
    Factory de dependency : génère une vérification de rôle sur-mesure.

    Usage dans une route :
        @router.post("/analyze", dependencies=[Depends(require_roles("admin", "analyst"))])

    Si le rôle de l'utilisateur connecté n'est pas dans allowed_roles → 403 Forbidden.
    """
    def role_checker(current_user: UserORM = Depends(get_current_user)) -> UserORM:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Accès refusé : rôle '{current_user.role}' insuffisant pour cette action"
            )
        return current_user
    return role_checker


# Raccourcis pratiques pour les combinaisons les plus utilisées dans le projet
require_admin = require_roles("admin")
require_analyst_or_admin = require_roles("admin", "analyst")
require_any_role = require_roles("admin", "analyst", "auditor")
