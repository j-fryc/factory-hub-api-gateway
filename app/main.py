from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth
from .config import get_settings
from .auth.auth_manager import OAuthManager
from app.auth.routers import router as auth_router

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
    app.state.oauth_service = oauth_manager

app.include_router(auth_router)
