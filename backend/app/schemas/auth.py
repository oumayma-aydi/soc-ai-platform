from pydantic import BaseModel, ConfigDict


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    role: str


class RefreshRequest(BaseModel):
    refresh_token: str


class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    role: str = "analyst"


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)  # permet de renvoyer directement un objet UserORM

    id: str
    username: str
    email: str
    role: str
    is_active: int