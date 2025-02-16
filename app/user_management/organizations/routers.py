from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse

from app.roles_handler.roles_manager import verify_current_user
from app.roles_handler.roles_schema import ApplicationRoles, OrganisationRoles
from app.user_management.organizations.schemas import SortParameters, CreateOrganizationFields, \
    UpdateOrganizationFields, AddDeleteMembersFields
from app.user_management.roles.schemas import UserRolesFields
from app.utils.request_exceptions import BadRequestException, ServiceUnavailableException, BaseApiException
from app.utils.request_handler import get_request_handler, RequestHandler


router = APIRouter(prefix="/api/v1/organizations")


@router.get("/")
async def get_organizations(
        user_role: dict = Depends(verify_current_user(
            [
                ApplicationRoles.APPLICATION_ADMIN.value,
                OrganisationRoles.ORGANISATION_ADMIN.value
            ]
        )),
        sort_parameter: SortParameters = Depends(),
        request_handler: RequestHandler = Depends(get_request_handler)
):
    try:
        organization_info = await request_handler.make_request(
            method="GET",
            endpoint='http://host.docker.internal:8001/api/v1/organizations/',
            params=sort_parameter.dict(exclude_none=True)
        )
        return JSONResponse(content=organization_info)
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


@router.post("/")
async def create_organizations(
        user_role: dict = Depends(verify_current_user(
            [
                ApplicationRoles.APPLICATION_ADMIN.value,
            ]
        )),
        create_organization_parameter: CreateOrganizationFields = Depends(),
        request_handler: RequestHandler = Depends(get_request_handler)
):
    try:
        organization_info = await request_handler.make_request(
            method="POST",
            endpoint='http://host.docker.internal:8001/api/v1/organizations/',
            content=create_organization_parameter.model_dump_json(exclude_none=True)
        )
        return JSONResponse(content=organization_info)
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


@router.patch("/{organization_id}")
async def update_organizations(
        organization_id: str,
        user_role: dict = Depends(verify_current_user(
            [
                ApplicationRoles.APPLICATION_ADMIN.value,
                OrganisationRoles.ORGANISATION_ADMIN.value
            ]
        )),
        update_organization_parameter: UpdateOrganizationFields = Depends(),
        request_handler: RequestHandler = Depends(get_request_handler)
):
    try:
        organization_info = await request_handler.make_request(
            method="PATCH",
            endpoint=f'http://host.docker.internal:8001/api/v1/organizations/{organization_id}',
            content=update_organization_parameter.model_dump_json(exclude_none=True)
        )
        return JSONResponse(content=organization_info)
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


@router.delete("/{organization_id}")
async def delete_organization(
        organization_id: str,
        user_role: dict = Depends(verify_current_user(
            [
                ApplicationRoles.APPLICATION_ADMIN.value,
                OrganisationRoles.ORGANISATION_ADMIN.value
            ]
        )),
        request_handler: RequestHandler = Depends(get_request_handler)
):
    try:
        organization_info = await request_handler.make_request(
            method="DELETE",
            endpoint=f'http://host.docker.internal:8001/api/v1/organizations/{organization_id}'
        )
        return JSONResponse(content=organization_info)
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


@router.post("/{organization_id}/members")
async def add_users_to_organization(
        organization_id: str,
        members_list: AddDeleteMembersFields,
        user_role: dict = Depends(verify_current_user(
            [
                ApplicationRoles.APPLICATION_ADMIN.value,
                OrganisationRoles.ORGANISATION_ADMIN.value,
                OrganisationRoles.ORGANISATION_MANAGER.value,
            ]
        )),
        request_handler: RequestHandler = Depends(get_request_handler)
):
    try:
        organization_info = await request_handler.make_request(
            method="POST",
            endpoint=f'http://host.docker.internal:8001/api/v1/organizations/{organization_id}/members',
            content=members_list.model_dump_json(exclude_none=True)
        )
        return JSONResponse(content=organization_info)
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


@router.delete("/{organization_id}/members")
async def delete_users_from_organization(
        organization_id: str,
        members_list: AddDeleteMembersFields,
        user_role: dict = Depends(verify_current_user(
            [
                ApplicationRoles.APPLICATION_ADMIN.value,
                OrganisationRoles.ORGANISATION_ADMIN.value,
                OrganisationRoles.ORGANISATION_MANAGER.value,
            ]
        )),
        request_handler: RequestHandler = Depends(get_request_handler)
):
    try:
        organization_info = await request_handler.make_request(
            method="DELETE",
            endpoint=f'http://host.docker.internal:8001/api/v1/organizations/{organization_id}/members',
            content=members_list.model_dump_json(exclude_none=True)
        )
        return JSONResponse(content=organization_info)
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


@router.get("/{organization_id}/members/{user_id}/roles")
async def get_organization_roles(
        organization_id: str,
        user_id: str,
        user_role: dict = Depends(verify_current_user(
            [
                ApplicationRoles.APPLICATION_ADMIN.value,
                OrganisationRoles.ORGANISATION_ADMIN.value,
                OrganisationRoles.ORGANISATION_MANAGER.value,
            ]
        )),
        request_handler: RequestHandler = Depends(get_request_handler)
):
    try:
        organization_info = await request_handler.make_request(
            method="GET",
            endpoint=f'http://host.docker.internal:8001/api/v1/organizations/{organization_id}/members/{user_id}/roles',
        )
        return JSONResponse(content=organization_info)
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


@router.delete("/{organization_id}/members/{user_id}/roles")
async def delete_users_roles_from_organization_member(
        organization_id: str,
        user_id: str,
        members_roles_fields: UserRolesFields,
        user_role: dict = Depends(verify_current_user(
            [
                ApplicationRoles.APPLICATION_ADMIN.value,
                OrganisationRoles.ORGANISATION_ADMIN.value,
            ]
        )),
        request_handler: RequestHandler = Depends(get_request_handler)
):
    try:
        organization_info = await request_handler.make_request(
            method="DELETE",
            endpoint=f'http://host.docker.internal:8001/api/v1/organizations/{organization_id}/members/{user_id}/roles',
            content=members_roles_fields.model_dump_json(exclude_none=True)
        )
        return JSONResponse(content=organization_info)
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


@router.post("/{organization_id}/members/{user_id}/roles")
async def assign_user_roles_in_organization(
        organization_id: str,
        user_id: str,
        members_roles_fields: UserRolesFields,
        user_role: dict = Depends(verify_current_user(
            [
                ApplicationRoles.APPLICATION_ADMIN.value,
                OrganisationRoles.ORGANISATION_ADMIN.value,
            ]
        )),
        request_handler: RequestHandler = Depends(get_request_handler)
):
    try:
        organization_info = await request_handler.make_request(
            method="POST",
            endpoint=f'http://host.docker.internal:8001/api/v1/organizations/{organization_id}/members/{user_id}/roles',
            content=members_roles_fields.model_dump_json(exclude_none=True)
        )
        return JSONResponse(content=organization_info)
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