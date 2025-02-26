from typing import Optional

from pydantic import BaseModel, Field


class BaseRoleFields(BaseModel):
    description: str = Field(..., description="Description of the role")
    name: str = Field(..., description="Name of the role")


class RoleFields(BaseRoleFields):
    id: str = Field(..., description="Unique role ID")


class CreateRoleFields(BaseRoleFields):
    pass


class UpdateRoleFields(BaseModel):
    description: Optional[str] = Field(default=None, description="Description of the role")
    name: Optional[str] = Field(default=None, description="Name of the role")


class UserRolesFields(BaseModel):
    roles: list[str] = Field(..., description="List of roles")