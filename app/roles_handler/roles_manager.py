from typing import List

from authlib.jose import JoseError
from fastapi.security import SecurityScopes

from app.auth.auth_exceptions import TokenMissingException, TokenVerifierException
from app.auth.auth_manager import OAuthManager

from fastapi import Request, HTTPException

from app.config import Settings


class RolesManager:
    def __init__(self, settings: Settings, auth_manager_service: OAuthManager):
        self._settings = settings
        self._auth_manager = auth_manager_service

    async def verify_token_with_scopes(
            self,
            request: Request,
            security_scopes: SecurityScopes,
    ) -> dict:
        try:
            token_claims = await self._auth_manager.verify_token(request)
        except (JoseError, TokenMissingException):
            raise HTTPException(status_code=403, detail="Forbidden: Access denied")
        except TokenVerifierException:
            raise HTTPException(status_code=500, detail="Application internal error")
        user_roles = token_claims.get(f'{self._settings.name_space}/roles')
        if user_roles and any(role == scope for scope in security_scopes.scopes for role in user_roles):
            return token_claims
        raise HTTPException(
                status_code=403,
                detail=f"Insufficient permissions. Required: {security_scopes.scopes}",
            )


async def get_roles_manager(request: Request) -> RolesManager:
    return request.app.state.roles_manager


def verify_current_user(required_roles: List[str]):
    async def dependency(request: Request):
        roles_manager_instance = await get_roles_manager(request)
        security_scopes = SecurityScopes(scopes=required_roles)

        await roles_manager_instance.verify_token_with_scopes(
            request=request,
            security_scopes=security_scopes
        )
        return {"roles": required_roles}

    return dependency
