from fastapi import APIRouter, Depends
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse

from app.roles_handler.roles_manager import verify_current_user
from app.roles_handler.roles_schema import ApplicationRoles, OrganisationRoles
from app.user_management.roles.schemas import CreateRoleFields, UpdateRoleFields
from app.utils.dependencies import GetRolesServiceManager, UserRoles

router = APIRouter(prefix="/api/v1/roles")



@router.post("/")
async def create_role(
        roles_service_manager: GetRolesServiceManager,
        query_parameters: CreateRoleFields,
        user_role: UserRoles[
            ApplicationRoles.APPLICATION_ADMIN.value
        ],
):
    users_info = await roles_service_manager.create_role(query_parameters.model_dump(exclude_none=True))
    json_compatible_data = jsonable_encoder(users_info)
    return JSONResponse(content=json_compatible_data)


@router.delete("/{role_id}")
async def delete_role(
        roles_service_manager: GetRolesServiceManager,
        role_id: str,
        user_role: UserRoles[
            ApplicationRoles.APPLICATION_ADMIN.value
        ],
):
    await roles_service_manager.delete_role(role_id)
    return JSONResponse(status_code=204, content='Resource deleted successfully')


@router.patch("/{role_id}")
async def update_role(
        updating_fields: UpdateRoleFields,
        roles_service_manager: GetRolesServiceManager,
        role_id: str,
        user_role: UserRoles[[
                ApplicationRoles.APPLICATION_ADMIN.value,
                OrganisationRoles.ORGANISATION_ADMIN.value,
            ]],
):
    users_info = await roles_service_manager.update_role(role_id, updating_fields.model_dump(exclude_none=True))
    json_compatible_data = jsonable_encoder(users_info)
    return JSONResponse(content=json_compatible_data)


@router.get("/")
async def get_roles(
        roles_service_manager: GetRolesServiceManager,
        name_filter: str | None = None,
        user_role: dict = Depends(verify_current_user(
            [
                ApplicationRoles.APPLICATION_ADMIN.value,
                OrganisationRoles.ORGANISATION_ADMIN.value,
            ]
        )),
):
    users_info = await roles_service_manager.get_roles(name_filter)
    json_compatible_data = jsonable_encoder(users_info)
    return JSONResponse(content=json_compatible_data)
