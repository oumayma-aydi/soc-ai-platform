from pydantic import BaseModel, Field, validator
from typing import Literal
import re

UserRole = Literal["admin", "analyst", "auditor"]

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: str = Field(...)
    password: str = Field(..., description="Mot de passe en clair, soumis aux règles ANSSI")
    role: UserRole = Field(default="analyst")

    @validator("password")
    def check_password_strength(cls, v):
        if len(v) < 12:
            raise ValueError("Le mot de passe doit contenir au moins 12 caractères.")
        if not re.search(r"[A-Z]", v):
            raise ValueError("Le mot de passe doit contenir au moins une majuscule.")
        if not re.search(r"[a-z]", v):
            raise ValueError("Le mot de passe doit contenir au moins une minuscule.")
        if not re.search(r"[0-9]", v):
            raise ValueError("Le mot de passe doit contenir au moins un chiffre.")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>_+-]", v):
            raise ValueError("Le mot de passe doit contenir au moins un caractère spécial.")
        return v

class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    role: UserRole
    is_active: int

    class Config:
        from_attributes = True
        orm_mode = True  # Double compatibilité Pydantic v1/v2

class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    role: UserRole

class RefreshRequest(BaseModel):
    refresh_token: str
