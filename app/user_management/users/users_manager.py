from typing import List
from urllib.parse import urljoin

from app.user_management.roles.schemas import RoleFields, UserRolesFields
from app.user_management.users.schemas import SearchableUserFields, CreateUserFields, UpdateUserFields, UserFields
from app.utils.base_manager import BaseManager

from fastapi import Request


class UserServiceManager(BaseManager):

    @property
    def _api_endpoint(self) -> str:
        return f"{self._settings.factory_hub_user_mgmt_endpoint}/users/"

    async def create_user(self, query_parameters: CreateUserFields) -> UserFields:
        created_user_data = await self._send_request(
            method="POST",
            endpoint=self._api_endpoint,
            params=query_parameters.dict(exclude_none=True)
        )
        return UserFields(**created_user_data)

    async def get_users(self, query_parameters: SearchableUserFields) -> List[UserFields]:
        users_data = await self._send_request(
            method="GET",
            endpoint=self._api_endpoint,
            params=query_parameters.dict(exclude_none=True)
        )
        return [UserFields(**user_data) for user_data in users_data]

    async def delete_user(self, user_id: str) -> None:
        return await self._send_request(
            method="DELETE",
            endpoint=urljoin(self._api_endpoint, user_id)
        )

    async def update_user(self, user_id: str, updating_fields: UpdateUserFields) -> UserFields:
        updated_user_data = await self._send_request(
            method="PATCH",
            endpoint=urljoin(self._api_endpoint, user_id),
            content=updating_fields.model_dump_json(exclude_none=True)
        )
        return UserFields(**updated_user_data)

    async def get_user_roles(self, user_id: str) -> list[RoleFields] | list:
        user_roles = await self._send_request(
            method="GET",
            endpoint=urljoin(self._api_endpoint, ''.join([user_id, "/roles"])),
        )
        return [RoleFields(**user_role) for user_role in user_roles]

    async def delete_users_roles(self, user_id: str, members_roles_fields: UserRolesFields) -> None:
        return await self._send_request(
            method="DELETE",
            endpoint=urljoin(self._api_endpoint, ''.join([user_id, "/roles"])),
            content=members_roles_fields.model_dump_json(exclude_none=True)
        )

    async def assign_user_roles(self, user_id: str, members_roles_fields: UserRolesFields) -> None:
        return await self._send_request(
            method="POST",
            endpoint=urljoin(self._api_endpoint, ''.join([user_id, "/roles"])),
            content=members_roles_fields.model_dump_json(exclude_none=True)
        )


async def get_users_service_manager(request: Request) -> UserServiceManager:
    return request.app.state.users_service_manager
