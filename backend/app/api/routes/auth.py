from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from jose import JWTError

from app.core.database import get_db
from app.core.security import create_access_token, create_refresh_token, decode_token
from app.core.dependencies import require_admin
from app.services.user_service import authenticate_user, create_user
from app.schemas.auth import LoginRequest, TokenResponse, RefreshRequest, UserCreate, UserResponse
from app.models.orm import UserORM

router = APIRouter()


@router.post("/login", response_model=TokenResponse)
def login(credentials: LoginRequest, db: Session = Depends(get_db)):
    """Authentifie un utilisateur et retourne un access_token + refresh_token."""
    user = authenticate_user(db, credentials.username, credentials.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nom d'utilisateur ou mot de passe incorrect"
        )

    token_payload = {"sub": user.username, "role": user.role}
    return TokenResponse(
        access_token=create_access_token(token_payload),
        refresh_token=create_refresh_token(token_payload),
        role=user.role
    )


@router.post("/refresh", response_model=TokenResponse)
def refresh(payload: RefreshRequest, db: Session = Depends(get_db)):
    """Échange un refresh_token valide contre un nouveau access_token."""
    try:
        decoded = decode_token(payload.refresh_token)
        if decoded.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Token fourni n'est pas un refresh_token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Refresh token invalide ou expiré")

    username = decoded.get("sub")
    from app.services.user_service import get_user_by_username
    user = get_user_by_username(db, username)
    if not user or user.is_active != 1:
        raise HTTPException(status_code=401, detail="Utilisateur introuvable ou désactivé")

    token_payload = {"sub": user.username, "role": user.role}
    return TokenResponse(
        access_token=create_access_token(token_payload),
        refresh_token=create_refresh_token(token_payload),
        role=user.role
    )


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(
    new_user: UserCreate,
    db: Session = Depends(get_db),
    current_admin: UserORM = Depends(require_admin)
):
    """
    Crée un nouvel utilisateur (analyst, auditor, ou admin).
    Réservé au Super Admin — protégé par require_admin.
    """
    try:
        user = create_user(db, new_user.username, new_user.email, new_user.password, new_user.role)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    return user
