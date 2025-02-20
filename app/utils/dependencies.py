from typing import Annotated, Generic, TypeVar, Type

from fastapi import Depends

from app.roles_handler.roles_manager import verify_current_user
from app.user_management.organizations.organizations_manager import get_organisations_service_manager, \
    OrganizationManager
from app.user_management.roles.roles_service_manager import RolesServiceManager, get_roles_service_manager
from app.user_management.users.users_manager import get_users_service_manager, UserServiceManager

T = TypeVar("T")


class UserRoles(Generic[T]):
    def __class_getitem__(cls, roles: list[str]) -> Annotated[Type[dict], Depends()]:
        return Annotated[dict, Depends(verify_current_user(roles))]


GetRolesServiceManager = Annotated[RolesServiceManager, Depends(get_roles_service_manager), ]
GetOrganisationsServiceManager = Annotated[OrganizationManager, Depends(get_organisations_service_manager), ]
GetUsersServiceManager = Annotated[UserServiceManager, Depends(get_users_service_manager), ]