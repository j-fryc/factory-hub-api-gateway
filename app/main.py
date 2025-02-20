from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth
from .config import get_settings
from .auth.auth_manager import OAuthManager
from app.auth.routers import router as auth_router
from app.user_management.organizations.routers import router as organization_management_router
from app.user_management.roles.routers import router as role_management_router
from app.user_management.users.routers import router as user_management_router
from .roles_handler.roles_manager import RolesManager
from .user_management.organizations.organizations_manager import OrganizationManager
from .user_management.roles.roles_service_manager import RolesServiceManager
from .user_management.users.users_manager import UserServiceManager

app = FastAPI()

settings = get_settings()

app.add_middleware(
    SessionMiddleware,
    secret_key=settings.secret_key,
    session_cookie="fastapi_session",
    max_age=3600,
)


@app.on_event("startup")
async def startup():
    oauth_manager = OAuthManager(
        settings=get_settings(),
        oauth_service=OAuth()
    )
    oauth_manager.register_oauth()
    roles_manager = RolesManager(
        settings=get_settings(),
        auth_manager_service=oauth_manager
    )
    roles_service_manager = RolesServiceManager(
        settings=get_settings()
    )
    organisation_service_manager = OrganizationManager(
        settings=get_settings()
    )
    users_service_manager = UserServiceManager(
        settings=get_settings()
    )
    app.state.oauth_service = oauth_manager
    app.state.roles_manager = roles_manager
    app.state.roles_service_manager = roles_service_manager
    app.state.organisation_service_manager = organisation_service_manager
    app.state.users_service_manager = users_service_manager

app.include_router(auth_router)
app.include_router(user_management_router)
app.include_router(organization_management_router)
app.include_router(role_management_router)
