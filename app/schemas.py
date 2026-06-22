"""Esquemas Pydantic (validación y serialización)."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class UserCreate(BaseModel):
    username: str
    password: str


class UserOut(BaseModel):
    id: int
    username: str
    created_at: datetime

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class ProjectCreate(BaseModel):
    name: str
    description: Optional[str] = ""


class ProjectOut(BaseModel):
    id: int
    name: str
    description: str
    owner_id: Optional[int]
    created_at: datetime

    class Config:
        from_attributes = True


class TaskCreate(BaseModel):
    title: str
    description: Optional[str] = ""
    status: Optional[str] = "todo"
    priority: Optional[int] = 3
    project_id: int


class TaskOut(BaseModel):
    id: int
    title: str
    description: str
    status: str
    priority: int
    project_id: Optional[int]
    created_at: datetime

    class Config:
        from_attributes = True
