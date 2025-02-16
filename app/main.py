from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth
from .config import get_settings
from .auth.auth_manager import OAuthManager
from app.auth.routers import router as auth_router
from app.user_management.organizations.routers import router as organization_management_router
from app.user_management.roles.routers import router as role_management_router
from app.user_management.users.routers import router as user_management_router
from app.utils.request_handler import RequestHandler
from .roles_handler.roles_manager import RolesManager

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
    request_handler = RequestHandler()
    app.state.oauth_service = oauth_manager
    app.state.roles_manager = roles_manager
    app.state.request_handler = request_handler

app.include_router(auth_router)
app.include_router(user_management_router)
app.include_router(organization_management_router)
app.include_router(role_management_router)
