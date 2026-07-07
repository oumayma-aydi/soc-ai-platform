from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from jose import JWTError
from pydantic import BaseModel

from app.core.database import get_db
from app.core.security import create_access_token, create_refresh_token, decode_token
from app.core.dependencies import require_admin, get_current_user, VALID_ROLES
from app.services.user_service import (
    authenticate_user, create_user, get_user_by_username,
    initiate_password_reset, reset_password_with_token, admin_set_user_password,
)
from app.schemas.auth import LoginRequest, TokenResponse, RefreshRequest, UserCreate, UserResponse
from app.models.orm import UserORM, PasswordResetRequestORM

from app.services.user_service import verify_admin_password

router = APIRouter()


# ============================================================
#  AUTHENTIFICATION DE BASE
# ============================================================

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
    """Crée un nouvel utilisateur (analyst, auditor, ou admin). Réservé à l'admin."""
    try:
        user = create_user(db, new_user.username, new_user.email, new_user.password, new_user.role)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    return user


# ============================================================
#  RÉINITIALISATION DE MOT DE PASSE
# ============================================================

class ForgotPasswordRequest(BaseModel):
    username_or_email: str


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str


class AdminSetPasswordRequest(BaseModel):
    new_password: str


@router.post("/forgot-password")
def forgot_password(payload: ForgotPasswordRequest, db: Session = Depends(get_db)):
    """
    Point d'entrée unique pour les 3 rôles.
    - admin -> reçoit un lien de réinitialisation par e-mail (auto-service)
    - analyst/auditor -> notification envoyée aux admins, traitement manuel
    Réponse volontairement identique dans tous les cas (anti-énumération de comptes).
    """
    initiate_password_reset(db, payload.username_or_email)
    return {"message": "Si ce compte existe, la procédure de réinitialisation a été initiée."}


@router.post("/reset-password")
def reset_password(payload: ResetPasswordRequest, db: Session = Depends(get_db)):
    """Auto-service admin uniquement, via le lien reçu par e-mail."""
    reset_password_with_token(db, payload.token, payload.new_password)
    return {"message": "Mot de passe réinitialisé avec succès."}


@router.get("/admin/password-reset-requests")
def list_reset_requests(
    db: Session = Depends(get_db),
    current_admin: UserORM = Depends(require_admin),
):
    """Liste les demandes de réinitialisation en attente pour analyst/auditor."""
    requests = (
        db.query(PasswordResetRequestORM)
        .filter(PasswordResetRequestORM.resolved == 0)
        .order_by(PasswordResetRequestORM.requested_at.desc())
        .all()
    )
    return [
        {
            "id": r.id,
            "user_id": r.user_id,
            "username": r.user.username,
            "role": r.user.role,
            "requested_at": r.requested_at.isoformat(),
        }
        for r in requests
    ]


@router.post("/admin/set-password/{user_id}")
def admin_reset_user_password(
    user_id: str,
    payload: AdminSetPasswordRequest,
    db: Session = Depends(get_db),
    current_admin: UserORM = Depends(require_admin),
):
    """L'admin définit lui-même un nouveau mot de passe pour un analyst/auditor."""
    target = db.query(UserORM).filter(UserORM.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable.")
    admin_set_user_password(db, target, payload.new_password, current_admin.username)
    return {"message": f"Mot de passe de {target.username} mis à jour."}


# ============================================================
#  GESTION DES COMPTES (liste, changement de rôle, suppression)
# ============================================================

class UpdateRoleRequest(BaseModel):
    role: str
    confirm_password: str


class AdminSetPasswordRequest(BaseModel):
    new_password: str
    confirm_password: str


class DeleteAccountRequest(BaseModel):
    confirm_password: str
    
class UpdateEmailRequest(BaseModel):
    new_email: str
    confirm_password: str


@router.get("/users")
def list_users(
    db: Session = Depends(get_db),
    current_admin: UserORM = Depends(require_admin),
):
    """Liste tous les comptes — jamais le hash du mot de passe, jamais consultable en clair."""
    users = db.query(UserORM).order_by(UserORM.username).all()
    return [
        {
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "role": u.role,
            "is_active": u.is_active,
            "password_updated_at": u.password_updated_at.isoformat() if u.password_updated_at else None,
        }
        for u in users
    ]


@router.patch("/users/{user_id}/role")
def update_user_role(
    user_id: str,
    payload: UpdateRoleRequest,
    db: Session = Depends(get_db),
    current_admin: UserORM = Depends(require_admin),
):
    verify_admin_password(db, current_admin, payload.confirm_password)

    if payload.role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail=f"Rôle invalide. Rôles valides : {VALID_ROLES}")

    target = db.query(UserORM).filter(UserORM.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable.")

    if target.id == current_admin.id and payload.role != "admin":
        raise HTTPException(status_code=400, detail="Vous ne pouvez pas retirer votre propre accès admin.")

    if payload.role == "admin" and target.role != "admin":
        from app.services.user_service import count_admins
        if count_admins(db) >= 1:
            raise HTTPException(status_code=409, detail="Un compte administrateur existe déjà.")

    target.role = payload.role
    db.commit()
    return {"message": f"Rôle de {target.username} changé en '{payload.role}'."}


@router.post("/admin/set-password/{user_id}")
def admin_reset_user_password(
    user_id: str,
    payload: AdminSetPasswordRequest,
    db: Session = Depends(get_db),
    current_admin: UserORM = Depends(require_admin),
):
    verify_admin_password(db, current_admin, payload.confirm_password)

    target = db.query(UserORM).filter(UserORM.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable.")
    admin_set_user_password(db, target, payload.new_password, current_admin.username)
    return {"message": f"Mot de passe de {target.username} mis à jour."}


@router.delete("/users/{user_id}")
def delete_user(
    user_id: str,
    payload: DeleteAccountRequest,
    db: Session = Depends(get_db),
    current_admin: UserORM = Depends(require_admin),
):
    verify_admin_password(db, current_admin, payload.confirm_password)

    target = db.query(UserORM).filter(UserORM.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable.")

    if target.id == current_admin.id:
        raise HTTPException(status_code=400, detail="Vous ne pouvez pas supprimer votre propre compte.")

    username = target.username
    db.delete(target)
    db.commit()
    return {"message": f"Compte {username} supprimé."}

@router.post("/admin/unlock/{user_id}")
def unlock_user_account(
    user_id: str,
    payload: DeleteAccountRequest,  # réutilise le même schéma { confirm_password }
    db: Session = Depends(get_db),
    current_admin: UserORM = Depends(require_admin),
):
    verify_admin_password(db, current_admin, payload.confirm_password)

    target = db.query(UserORM).filter(UserORM.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable.")

    target.is_active = 1
    target.failed_login_attempts = 0
    db.commit()
    return {"message": f"Compte {target.username} débloqué."}

@router.patch("/users/{user_id}/email")
def update_user_email(
    user_id: str,
    payload: UpdateEmailRequest,
    db: Session = Depends(get_db),
    current_admin: UserORM = Depends(require_admin),
):
    verify_admin_password(db, current_admin, payload.confirm_password)

    target = db.query(UserORM).filter(UserORM.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable.")

    target.email = payload.new_email
    db.commit()
    return {"message": f"E-mail de {target.username} mis à jour."}