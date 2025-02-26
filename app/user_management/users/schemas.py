from typing import Optional, Literal, List

from fastapi import Query
from pydantic import BaseModel, EmailStr, Field, HttpUrl


class SearchableUserFields(BaseModel):
    email: Optional[EmailStr] = Query(default=None, description="User's email address")
    created_at: Optional[str] = Query(default=None, description="Creation timestamp")
    organization_id: Optional[str] = Query(default=None, description="Organization ID associated with the user")
    name: Optional[str] = Query(default=None, description="User's full name")
    given_name: Optional[str] = Query(default=None, description="User's given name")
    family_name: Optional[str] = Query(default=None, description="User's family name")


class CreateUserFields(BaseModel):
    connection: Literal['Username-Password-Authentication'] = Field(
        default='Username-Password-Authentication',
        description="Connection type for the user"
    )
    email: EmailStr = Field(..., description="User's email address")
    password: str = Field(..., description="User's password")
    given_name: str = Field(..., description="User's given name")
    family_name: str = Field(..., description="User's family name")
    picture: Optional[str] = Field(default=None, description="URL to the user's profile picture")


class UpdateUserFields(BaseModel):
    email: Optional[EmailStr] = Field(default=None, description="User's email address")
    password: Optional[str] = Field(default=None, description="User's password")
    given_name: Optional[str] = Field(default=None, description="User's given name")
    family_name: Optional[str] = Field(default=None, description="User's family name")
    email_verified: Optional[bool] = Field(default=None, description="Indicates if the email is verified")
    phone_verified: Optional[bool] = Field(default=None, description="Indicates if the phone number is verified")
    picture: Optional[str] = Field(default=None, description="URL to the user's profile picture")


class Identity(BaseModel):
    connection: str = Field(..., description="The connection type for the identity")
    user_id: str = Field(..., description="The user ID for the identity")
    provider: str = Field(..., description="The provider for the identity")
    isSocial: bool = Field(..., description="Indicates whether the identity is social")


class UserFields(BaseModel):
    created_at: str = Field(..., description="Timestamp when the user was created")
    email: EmailStr = Field(..., description="User's email address")
    email_verified: bool = Field(..., description="Indicates whether the email is verified")
    identities: List[Identity] = Field(..., description="List of identities associated with the user")
    name: str = Field(..., description="Full name of the user")
    nickname: str = Field(..., description="Nickname of the user")
    picture: HttpUrl = Field(..., description="URL to the user's profile picture")
    updated_at: str = Field(..., description="Timestamp when the user was last updated")
    user_id: str = Field(..., description="Unique user ID")