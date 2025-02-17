from app.config import Settings
from app.user_management.roles.schemas import RoleFields
from app.utils.base_manager import BaseManager

from urllib.parse import urljoin

from fastapi import Request


class RolesServiceManager(BaseManager):
    def __init__(self, settings: Settings):
        super().__init__()
        self._settings = settings

    @property
    def _roles_endpoint(self) -> str:
        return f"{self._settings.factory_hub_user_mgmt_endpoint}/roles/"

    async def create_role(self, data: dict) -> RoleFields:
        created_role_data = await self._send_request(
            method="POST",
            endpoint=self._roles_endpoint,
            content=data
        )
        return RoleFields(**created_role_data)

    async def delete_role(self, role_id: str) -> None:
        return await self._send_request(
            method="DELETE",
            endpoint=urljoin(self._roles_endpoint, role_id)
        )

    async def update_role(self, role_id: str, data: dict):
        updated_role_data = await self._send_request(
            method="PATCH",
            endpoint=urljoin(self._roles_endpoint, role_id),
            content=data
        )
        return RoleFields(**updated_role_data)

    async def get_roles(self, name_filter: str | None = None):
        roles_data = await self._send_request(
            method="GET",
            endpoint=self._roles_endpoint,
            params={"name_filter": name_filter} if name_filter else {}
        )
        return [RoleFields(**role_data) for role_data in roles_data]


async def get_roles_service_manager(request: Request) -> RolesServiceManager:
    return request.app.state.roles_service_manager
