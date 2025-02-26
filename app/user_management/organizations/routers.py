from fastapi import APIRouter
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse

from app.roles_handler.roles_schema import ApplicationRoles, OrganisationRoles
from app.user_management.organizations.schemas import AddDeleteMembersFields, OrganisationSortParameters, \
    CreateOrganizationFields, UpdateOrganizationFields
from app.user_management.roles.schemas import UserRolesFields
from app.utils.dependencies import GetOrganisationsServiceManager, UserRoles

router = APIRouter(prefix="/api/v1/organizations")


@router.get("/")
async def get_organizations(
        query_parameters: OrganisationSortParameters,
        organisations_service_manager: GetOrganisationsServiceManager,
        user_role: UserRoles[[
            ApplicationRoles.APPLICATION_ADMIN.value,
            OrganisationRoles.ORGANISATION_ADMIN.value
        ]]
):
    organisations_info = await organisations_service_manager.get_organizations(sort_parameter=query_parameters)
    json_compatible_data = jsonable_encoder(organisations_info)
    return JSONResponse(content=json_compatible_data)


@router.post("/")
async def create_organizations(
        organisations_service_manager: GetOrganisationsServiceManager,
        query_parameters: CreateOrganizationFields,
        user_role: UserRoles[
            ApplicationRoles.APPLICATION_ADMIN.value
        ]
):
    created_organisation = await organisations_service_manager.create_organization(
        create_organization_parameter=query_parameters
    )
    json_compatible_data = jsonable_encoder(created_organisation)
    return JSONResponse(content=json_compatible_data)


@router.patch("/{organization_id}")
async def update_organizations(
        organisations_service_manager: GetOrganisationsServiceManager,
        query_parameters: UpdateOrganizationFields,
        organization_id: str,
        user_role: UserRoles[[
                ApplicationRoles.APPLICATION_ADMIN.value,
                OrganisationRoles.ORGANISATION_ADMIN.value,
            ]],
):
    updated_organisation = await organisations_service_manager.update_organization(
        organization_id=organization_id,
        update_organization_parameter=query_parameters,
    )
    json_compatible_data = jsonable_encoder(updated_organisation)
    return JSONResponse(content=json_compatible_data)


@router.delete("/{organization_id}")
async def delete_organization(
        organisations_service_manager: GetOrganisationsServiceManager,
        organization_id: str,
        user_role: UserRoles[[
                ApplicationRoles.APPLICATION_ADMIN.value,
                OrganisationRoles.ORGANISATION_ADMIN.value,
            ]],
):
    await organisations_service_manager.delete_organization(organization_id=organization_id)
    return JSONResponse(status_code=204, content='Resource deleted successfully')


@router.post("/{organization_id}/members")
async def add_users_to_organization(
        organisations_service_manager: GetOrganisationsServiceManager,
        organization_id: str,
        members_list: AddDeleteMembersFields,
        user_role: UserRoles[[
            ApplicationRoles.APPLICATION_ADMIN.value,
            OrganisationRoles.ORGANISATION_ADMIN.value,
            OrganisationRoles.ORGANISATION_MANAGER.value,
        ]]
):
    await organisations_service_manager.add_users_to_organization(
        organization_id=organization_id,
        members_list=members_list
    )
    return JSONResponse(status_code=201, content='Resource added successfully')


@router.delete("/{organization_id}/members")
async def delete_users_from_organization(
        organisations_service_manager: GetOrganisationsServiceManager,
        organization_id: str,
        members_list: AddDeleteMembersFields,
        user_role: UserRoles[[
            ApplicationRoles.APPLICATION_ADMIN.value,
            OrganisationRoles.ORGANISATION_ADMIN.value,
            OrganisationRoles.ORGANISATION_MANAGER.value,
        ]]
):
    await organisations_service_manager.delete_users_from_organization(
        organization_id=organization_id,
        members_list=members_list
    )
    return JSONResponse(status_code=204, content='Resource deleted successfully')


@router.get("/{organization_id}/members/{user_id}/roles")
async def get_organization_roles(
        organisations_service_manager: GetOrganisationsServiceManager,
        organization_id: str,
        user_id: str,
        user_role: UserRoles[[
            ApplicationRoles.APPLICATION_ADMIN.value,
            OrganisationRoles.ORGANISATION_ADMIN.value,
            OrganisationRoles.ORGANISATION_MANAGER.value,
        ]]
):
    user_organisation_roles = await organisations_service_manager.get_user_roles_in_organization(
        organization_id=organization_id,
        user_id=user_id
    )
    json_compatible_data = jsonable_encoder(user_organisation_roles)
    return JSONResponse(content=json_compatible_data)


@router.delete("/{organization_id}/members/{user_id}/roles")
async def delete_users_roles_from_organization_member(
        organisations_service_manager: GetOrganisationsServiceManager,
        organization_id: str,
        user_id: str,
        members_roles_fields: UserRolesFields,
        user_role: UserRoles[[
                ApplicationRoles.APPLICATION_ADMIN.value,
                OrganisationRoles.ORGANISATION_ADMIN.value,
            ]],
):
    await organisations_service_manager.delete_user_roles_in_organization(
        organization_id=organization_id,
        user_id=user_id,
        members_roles_fields=members_roles_fields
    )
    return JSONResponse(status_code=204, content='Resource deleted successfully')


@router.post("/{organization_id}/members/{user_id}/roles")
async def assign_user_roles_in_organization(
        organisations_service_manager: GetOrganisationsServiceManager,
        organization_id: str,
        user_id: str,
        members_roles_fields: UserRolesFields,
        user_role: UserRoles[[
                ApplicationRoles.APPLICATION_ADMIN.value,
                OrganisationRoles.ORGANISATION_ADMIN.value,
            ]],
):
    await organisations_service_manager.assign_user_roles_in_organization(
        organization_id=organization_id,
        user_id=user_id,
        members_roles_fields=members_roles_fields
    )
    return JSONResponse(status_code=201, content='Resource successfully updated')
