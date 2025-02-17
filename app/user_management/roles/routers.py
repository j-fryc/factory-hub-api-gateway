from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from app.roles_handler.roles_manager import verify_current_user
from app.roles_handler.roles_schema import ApplicationRoles, OrganisationRoles
from app.user_management.roles.roles_service_manager import get_roles_service_manager, RolesServiceManager
from app.user_management.roles.schemas import CreateRoleFields, UpdateRoleFields


router = APIRouter(prefix="/api/v1/roles")



@router.post("/")
async def create_role(
        query_parameters: CreateRoleFields = Depends(),
        user_role: dict = Depends(verify_current_user(
            [ApplicationRoles.APPLICATION_ADMIN.value]
        )),
        roles_service_manager: RolesServiceManager = Depends(get_roles_service_manager)
):
    users_info = await roles_service_manager.create_role(query_parameters.model_dump(exclude_none=True))
    return JSONResponse(content=users_info)


@router.delete("/{role_id}")
async def delete_role(
        role_id: str,
        user_role: dict = Depends(verify_current_user(
            [ApplicationRoles.APPLICATION_ADMIN.value]
        )),
        roles_service_manager: RolesServiceManager = Depends(get_roles_service_manager)
):
    users_info = await roles_service_manager.delete_role(role_id)
    return JSONResponse(content=users_info)


@router.patch("/{role_id}")
async def update_role(
        role_id: str,
        updating_fields: UpdateRoleFields = Depends(),
        user_role: dict = Depends(verify_current_user(
            [
                ApplicationRoles.APPLICATION_ADMIN.value,
                OrganisationRoles.ORGANISATION_ADMIN.value,
            ]
        )),
        roles_service_manager: RolesServiceManager = Depends(get_roles_service_manager)
):
    users_info = await roles_service_manager.update_role(role_id, updating_fields.model_dump(exclude_none=True))
    return JSONResponse(content=users_info)


@router.get("/")
async def get_roles(
        name_filter: str | None = None,
        user_role: dict = Depends(verify_current_user(
            [
                ApplicationRoles.APPLICATION_ADMIN.value,
                OrganisationRoles.ORGANISATION_ADMIN.value,
            ]
        )),
        roles_service_manager: RolesServiceManager = Depends(get_roles_service_manager)
):
    users_info = await roles_service_manager.get_roles(name_filter)
    return JSONResponse(content=users_info)
