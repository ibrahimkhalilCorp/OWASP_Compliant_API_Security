from pydantic import BaseModel, EmailStr

from enum import Enum

class UserRole(str, Enum):
    admin = "admin"
    manager = "manager"
    agent = "agent"
    user = "user"

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class RegistrationRequest(BaseModel):
    email: EmailStr
    password: str

class RoleUpdateRequest(BaseModel):
    email: EmailStr
    role: UserRole

# class TokenResponse(BaseModel):
#     access_token: str
#     token_type: str = "bearer"
