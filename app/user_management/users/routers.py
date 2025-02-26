from fastapi import APIRouter
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse

from app.roles_handler.roles_schema import ApplicationRoles, OrganisationRoles
from app.user_management.roles.schemas import UserRolesFields
from app.user_management.users.schemas import UpdateUserFields, SearchableUserFields, CreateUserFields
from app.utils.dependencies import GetUsersServiceManager, UserRoles

router = APIRouter(prefix="/api/v1/users")


@router.post("/")
async def create_user(
        query_parameters: CreateUserFields,
        users_service_manager: GetUsersServiceManager,
        user_role: UserRoles[[
                ApplicationRoles.APPLICATION_ADMIN.value,
                OrganisationRoles.ORGANISATION_ADMIN.value,
            ]],
):
    created_user = await users_service_manager.create_user(query_parameters=query_parameters)
    json_compatible_data = jsonable_encoder(created_user)
    return JSONResponse(content=json_compatible_data)


@router.get('/')
async def get_users(
        query_parameters: SearchableUserFields,
        users_service_manager: GetUsersServiceManager,
        user_role: UserRoles[[
                ApplicationRoles.APPLICATION_ADMIN.value,
                OrganisationRoles.ORGANISATION_ADMIN.value,
            ]],
):
    users_info = await users_service_manager.get_users(query_parameters=query_parameters)
    json_compatible_data = jsonable_encoder(users_info)
    return JSONResponse(content=json_compatible_data)


@router.delete("/{user_id}")
async def delete_user(
        users_service_manager: GetUsersServiceManager,
        user_id: str,
        user_role: UserRoles[
            ApplicationRoles.APPLICATION_ADMIN.value
        ]
):
    await users_service_manager.delete_user(user_id=user_id)
    return JSONResponse(status_code=204, content='Resource deleted successfully')



@router.patch("/{user_id}")
async def update_user(
        users_service_manager: GetUsersServiceManager,
        user_id: str,
        updating_fields: UpdateUserFields,
        user_role: UserRoles[
            ApplicationRoles.APPLICATION_ADMIN.value
        ]
):
    updated_user_data = await users_service_manager.update_user(user_id=user_id, updating_fields=updating_fields)
    json_compatible_data = jsonable_encoder(updated_user_data)
    return JSONResponse(content=json_compatible_data)


@router.get("/{user_id}/roles")
async def get_user_roles(
        users_service_manager: GetUsersServiceManager,
        user_id: str,
        user_role: UserRoles[[
            ApplicationRoles.APPLICATION_ADMIN.value,
            OrganisationRoles.ORGANISATION_ADMIN.value,
            OrganisationRoles.ORGANISATION_MANAGER.value,
            OrganisationRoles.ORGANISATION_USER.value
        ]]
):
    users_roles = await users_service_manager.get_user_roles(user_id=user_id)
    json_compatible_data = jsonable_encoder(users_roles)
    return JSONResponse(content=json_compatible_data)


@router.delete("/{user_id}/roles")
async def delete_users_roles(
        users_service_manager: GetUsersServiceManager,
        user_id: str,
        organization_user_fields: UserRolesFields,
        user_role: UserRoles[[
                ApplicationRoles.APPLICATION_ADMIN.value,
                OrganisationRoles.ORGANISATION_ADMIN.value,
            ]],
):
    await users_service_manager.delete_users_roles(user_id=user_id, members_roles_fields=organization_user_fields)
    return JSONResponse(status_code=204, content='Resource deleted successfully')


@router.post("/{user_id}/roles")
async def assign_user_roles(
        users_service_manager: GetUsersServiceManager,
        user_id: str,
        organization_user_fields: UserRolesFields,
        user_role: UserRoles[[
                ApplicationRoles.APPLICATION_ADMIN.value,
                OrganisationRoles.ORGANISATION_ADMIN.value,
            ]],
):
    users_service_manager.assign_user_roles(user_id=user_id, members_roles_fields=organization_user_fields)
    return JSONResponse(status_code=201, content='Resource added successfully')
