from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse

from app.roles_handler.roles_manager import verify_current_user
from app.roles_handler.roles_schema import ApplicationRoles, OrganisationRoles
from app.user_management.roles.schemas import CreateRoleFields, UpdateRoleFields
from app.utils.request_exceptions import (
    BaseApiException,
    ServiceUnavailableException,
    BadRequestException
)
from app.utils.request_handler import RequestHandler, get_request_handler

router = APIRouter(prefix="/api/v1/roles")


@router.post("/")
async def create_role(
        user_role: dict = Depends(verify_current_user(
            [
                ApplicationRoles.APPLICATION_ADMIN.value,
            ]
        )),
        query_parameters: CreateRoleFields = Depends(),
        request_handler: RequestHandler = Depends(get_request_handler)
):
    try:
        users_info = await request_handler.make_request(
            method="POST",
            endpoint='http://host.docker.internal:8001/api/v1/roles/',
            content=query_parameters.model_dump_json(exclude_none=True)
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


@router.delete("/{role_id}")
async def delete_role(
        role_id: str,
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
            endpoint=f'http://host.docker.internal:8001/api/v1/roles/{role_id}',
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


@router.patch("/{role_id}")
async def update_role(
        role_id: str,
        user_role: dict = Depends(verify_current_user(
            [
                ApplicationRoles.APPLICATION_ADMIN.value,
                OrganisationRoles.ORGANISATION_ADMIN.value,
            ]
        )),
        updating_fields: UpdateRoleFields = Depends(),
        request_handler: RequestHandler = Depends(get_request_handler)
):
    try:
        users_info = await request_handler.make_request(
            method="PATCH",
            endpoint=f'http://host.docker.internal:8001/api/v1/roles/{role_id}',
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


@router.get("/")
async def get_roles(
        name_filter: str | None = None,
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
            method="PATCH",
            endpoint=f'http://host.docker.internal:8001/api/v1/roles/',
            params={'name_filter': name_filter} if name_filter else {}
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
