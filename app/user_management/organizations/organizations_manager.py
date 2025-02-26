from typing import List
from urllib.parse import urljoin

from app.user_management.organizations.schemas import (
    OrganisationSortParameters, CreateOrganizationFields, UpdateOrganizationFields, AddDeleteMembersFields, OrganizationFields
)
from app.user_management.roles.schemas import UserRolesFields, RoleFields
from app.utils.base_manager import BaseManager

from fastapi import Request


class OrganizationManager(BaseManager):

    @property
    def _api_endpoint(self) -> str:
        return f"{self._settings.factory_hub_user_mgmt_endpoint}/organizations/"

    async def get_organizations(
            self,
            sort_parameter: OrganisationSortParameters
    ) -> List[OrganizationFields]:
        organizations_data = await self._send_request(
            method="GET",
            endpoint=self._api_endpoint,
            params=sort_parameter.dict(exclude_none=True)
        )
        return [OrganizationFields(**organization_data) for organization_data in organizations_data]

    async def create_organization(
            self,
            create_organization_parameter: CreateOrganizationFields
    ) -> CreateOrganizationFields:
        created_organization_data = await self._send_request(
            method="POST",
            endpoint=self._api_endpoint,
            content=create_organization_parameter.model_dump_json(exclude_none=True)
        )
        return CreateOrganizationFields(**created_organization_data)

    async def update_organization(
            self,
            organization_id: str,
            update_organization_parameter: UpdateOrganizationFields
    ) -> OrganizationFields:
        updated_organizations_data = await self._send_request(
            method="PATCH",
            endpoint=urljoin(self._api_endpoint, organization_id),
            content=update_organization_parameter.model_dump_json(exclude_none=True)
        )
        return OrganizationFields(**updated_organizations_data)

    async def delete_organization(self, organization_id: str) -> None:
        return await self._send_request(
            method="DELETE",
            endpoint=urljoin(self._api_endpoint, organization_id)
        )

    async def add_users_to_organization(
            self,
            organization_id: str,
            members_list: AddDeleteMembersFields
    ) -> None:
        return await self._send_request(
            method="POST",
            endpoint=urljoin(self._api_endpoint, ''.join([organization_id, "/members"])),
            content=members_list.model_dump_json(exclude_none=True)
        )

    async def delete_users_from_organization(
            self,
            organization_id: str,
            members_list: AddDeleteMembersFields
    ) -> None:
        return await self._send_request(
            method="DELETE",
            endpoint=urljoin(self._api_endpoint, ''.join([organization_id, "/members"])),
            content=members_list.model_dump_json(exclude_none=True)
        )

    async def assign_user_roles_in_organization(
            self,
            organization_id: str,
            user_id: str,
            members_roles_fields: UserRolesFields
    ) -> None:
        return await self._send_request(
            method="POST",
            endpoint=urljoin(self._api_endpoint, ''.join([organization_id, "/members", user_id, "/roles"])),
            content=members_roles_fields.model_dump_json(exclude_none=True)
        )

    async def delete_user_roles_in_organization(
            self,
            organization_id: str,
            user_id: str,
            members_roles_fields: UserRolesFields
    ) -> None:
        return await self._send_request(
            method="DELETE",
            endpoint=urljoin(self._api_endpoint, ''.join([organization_id, "/members", user_id, "/roles"])),
            content=members_roles_fields.model_dump_json(exclude_none=True)
        )

    async def get_user_roles_in_organization(
            self,
            organization_id: str,
            user_id: str
    ) -> list[RoleFields] | list:
        organization_user_roles = await self._send_request(
            method="DELETE",
            endpoint=urljoin(self._api_endpoint, ''.join([organization_id, "/members", user_id, "/roles"])),
        )
        return [RoleFields(**organization_user_role) for organization_user_role in organization_user_roles]


async def get_organisations_service_manager(request: Request) -> OrganizationManager:
    return request.app.state.organisation_service_manager
