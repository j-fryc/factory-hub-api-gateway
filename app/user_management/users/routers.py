from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse

from app.roles_handler.roles_manager import verify_current_user
from app.roles_handler.roles_schema import ApplicationRoles, OrganisationRoles
from app.user_management.roles.schemas import UserRolesFields
from app.user_management.users.schemas import SearchableUserFields, CreateUserFields, UpdateUserFields
from app.utils.request_exceptions import BadRequestException, ServiceUnavailableException, BaseApiException
from app.utils.request_handler import get_request_handler, RequestHandler

router = APIRouter(prefix="/api/v1/users")


@router.post("/")
async def create_user(
        user_role: dict = Depends(verify_current_user(
            [
                ApplicationRoles.APPLICATION_ADMIN.value,
                OrganisationRoles.ORGANISATION_ADMIN.value,
            ]
        )),
        query_parameters: CreateUserFields = Depends(),
        request_handler: RequestHandler = Depends(get_request_handler)
):
    try:
        users_info = await request_handler.make_request(
            method="POST",
            endpoint='http://host.docker.internal:8001/api/v1/users/',
            params=query_parameters.dict(exclude_none=True)
        )
        return JSONResponse(content=users_info)
    except BadRequestException as e:
        raise HTTPException(
            status_code=400,
            detail=str(e)
        )
    except (ServiceUnavailableException, BaseApiException):
        raise HTTPException(
            status_code=500,
            detail="Service unavailable"
        )


@router.get('/')
async def get_users(
        user_role: dict = Depends(verify_current_user(
            [
                ApplicationRoles.APPLICATION_ADMIN.value,
                OrganisationRoles.ORGANISATION_ADMIN.value,
            ]
        )),
        query_parameters: SearchableUserFields = Depends(),
        request_handler: RequestHandler = Depends(get_request_handler)
):
    try:
        users_info = await request_handler.make_request(
            method="GET",
            endpoint='http://host.docker.internal:8001/api/v1/users/',
            params=query_parameters.dict(exclude_none=True)
        )
        return JSONResponse(content=users_info)
    except BadRequestException as e:
        raise HTTPException(
            status_code=400,
            detail=str(e)
        )
    except (ServiceUnavailableException, BaseApiException):
        raise HTTPException(
            status_code=500,
            detail="Service unavailable"
        )


@router.delete("/{user_id}")
async def delete_user(
        user_id: str,
        user_role: dict = Depends(verify_current_user(
            [
                ApplicationRoles.APPLICATION_ADMIN.value,
            ]
        )),
        request_handler: RequestHandler = Depends(get_request_handler)
):
    try:
        users_info = await request_handler.make_request(
            method="DELETE",
            endpoint=f'http://host.docker.internal:8001/api/v1/users/{user_id}',
        )
        return JSONResponse(content=users_info)
    except BadRequestException as e:
        raise HTTPException(
            status_code=400,
            detail=str(e)
        )
    except (ServiceUnavailableException, BaseApiException):
        raise HTTPException(
            status_code=500,
            detail="Service unavailable"
        )


@router.patch("/{user_id}")
async def update_user(
        user_id: str,
        updating_fields: UpdateUserFields,
        user_role: dict = Depends(verify_current_user(
            [
                ApplicationRoles.APPLICATION_ADMIN.value,
            ]
        )),
        request_handler: RequestHandler = Depends(get_request_handler)
):
    try:
        users_info = await request_handler.make_request(
            method="PATCH",
            endpoint=f'http://host.docker.internal:8001/api/v1/users/{user_id}',
            content=updating_fields.model_dump_json(exclude_none=True)
        )
        return JSONResponse(content=users_info)
    except BadRequestException as e:
        raise HTTPException(
            status_code=400,
            detail=str(e)
        )
    except (ServiceUnavailableException, BaseApiException):
        raise HTTPException(
            status_code=500,
            detail="Service unavailable"
        )


@router.get("/{user_id}/roles")
async def get_user_roles(
        user_id: str,
        user_role: dict = Depends(verify_current_user(
            [
                ApplicationRoles.APPLICATION_ADMIN.value,
                OrganisationRoles.ORGANISATION_ADMIN.value,
                OrganisationRoles.ORGANISATION_MANAGER.value,
                OrganisationRoles.ORGANISATION_USER.value
            ]
        )),
        request_handler: RequestHandler = Depends(get_request_handler)
):
    try:
        users_info = await request_handler.make_request(
            method="GET",
            endpoint=f'http://host.docker.internal:8001/api/v1/users/{user_id}/roles'
        )
        return JSONResponse(content=users_info)
    except BadRequestException as e:
        raise HTTPException(
            status_code=400,
            detail=str(e)
        )
    except (ServiceUnavailableException, BaseApiException):
        raise HTTPException(
            status_code=500,
            detail="Service unavailable"
        )


@router.delete("/{user_id}/roles")
async def delete_users_roles(
        user_id: str,
        organization_user_fields: UserRolesFields,
        user_role: dict = Depends(verify_current_user(
            [
                ApplicationRoles.APPLICATION_ADMIN.value,
                OrganisationRoles.ORGANISATION_ADMIN.value,
            ]
        )),
        request_handler: RequestHandler = Depends(get_request_handler)
):
    try:
        users_info = await request_handler.make_request(
            method="DELETE",
            endpoint=f'http://host.docker.internal:8001/api/v1/users/{user_id}/roles',
            content=organization_user_fields.model_dump_json(exclude_none=True)
        )
        return JSONResponse(content=users_info)
    except BadRequestException as e:
        raise HTTPException(
            status_code=400,
            detail=str(e)
        )
    except (ServiceUnavailableException, BaseApiException):
        raise HTTPException(
            status_code=500,
            detail="Service unavailable"
        )


@router.post("/{user_id}/roles")
async def assign_user_roles(
        user_id: str,
        organization_user_fields: UserRolesFields,
        user_role: dict = Depends(verify_current_user(
            [
                ApplicationRoles.APPLICATION_ADMIN.value,
                OrganisationRoles.ORGANISATION_ADMIN.value,
            ]
        )),
        request_handler: RequestHandler = Depends(get_request_handler)
):
    try:
        users_info = await request_handler.make_request(
            method="POST",
            endpoint=f'http://host.docker.internal:8001/api/v1/users/{user_id}/roles',
            content=organization_user_fields.model_dump_json(exclude_none=True)
        )
        return JSONResponse(content=users_info)
    except BadRequestException as e:
        raise HTTPException(
            status_code=400,
            detail=str(e)
        )
    except (ServiceUnavailableException, BaseApiException):
        raise HTTPException(
            status_code=500,
            detail="Service unavailable"
        )
