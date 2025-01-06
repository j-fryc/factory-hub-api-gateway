from fastapi import APIRouter, Depends, Request, Response, HTTPException
from starlette.responses import RedirectResponse

from app.auth.auth_manager import OAuthManager, get_oauth_service, OAuthServiceUnavailableException, \
    TokenExpiredException, TokenMissingException

router = APIRouter()


@router.get("/login")
async def login(request: Request, oauth_service: OAuthManager = Depends(get_oauth_service)):
    try:
        return await oauth_service.authorize_access(request)
    except OAuthServiceUnavailableException:
        raise HTTPException(
            status_code=503,
            detail="Server internal error",
        )


@router.get("/callback")
async def callback(request: Request, oauth_service: OAuthManager = Depends(get_oauth_service)):
    try:
        id_token = await oauth_service.get_access_token(request)
        response = RedirectResponse(url='/login-status')
        response.set_cookie(
            key="token_cookie",
            value=id_token,
            httponly=True,
            secure=True,
            samesite="lax"
        )
        return response
    except OAuthServiceUnavailableException:
        raise HTTPException(
            status_code=503,
            detail="Server internal error",
        )
    except TokenMissingException:
        return RedirectResponse(url='/login')


@router.get("/logout")
def logout(request: Request, response: Response, oauth_service: OAuthManager = Depends(get_oauth_service)):
    oauth_service.remove_token_cookie(request=request, response=response)
    return {"status": "logged out"}


@router.get("/login-status")
async def login_status(request: Request, oauth_service: OAuthManager = Depends(get_oauth_service)):
    try:
        await oauth_service.verify_token(request)
        return {"status": "authenticated"}
    except OAuthServiceUnavailableException as e:
        raise HTTPException(
            status_code=503,
            detail=f"Token verification failed: {e}",
        )
    except (TokenExpiredException, TokenMissingException):
        return RedirectResponse(url='/login')
