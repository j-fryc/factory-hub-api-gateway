from authlib.integrations.starlette_client import OAuth, OAuthError
from authlib.jose import jwt
from authlib.jose.errors import JoseError
from fastapi import Response, Request
from starlette.responses import RedirectResponse
from tenacity import retry, stop_after_attempt, retry_if_exception_type, wait_fixed

from app.auth.auth_token_verifier import TokenVerifier, TokenVerifierException
from app.config import Settings


class OAuthManagerException(Exception):
    pass


class OAuthServiceUnavailableException(OAuthManagerException):
    pass


class TokenExpiredException(OAuthManagerException):
    pass


class TokenMissingException(OAuthManagerException):
    pass


class OAuthManager:
    def __init__(self, settings: Settings, oauth_service: OAuth):
        self.settings = settings
        self.oauth = oauth_service
        self._token_verifier = TokenVerifier(domain=self.settings.auth0_domain)

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_fixed(2),
        retry=retry_if_exception_type(OAuthError)
    )
    def register_oauth(self):
        try:
            self.oauth.register(
                "auth0",
                client_id=self.settings.auth0_client_id,
                client_secret=self.settings.auth0_client_secret,
                client_kwargs={
                    "scope": "openid profile email",
                },
                server_metadata_url=f"https://{self.settings.auth0_domain}/.well-known/openid-configuration",
            )
        except OAuthError as e:
            raise OAuthServiceUnavailableException(f"Failed to register OAuth: {e}")

    async def verify_token(self, request: Request) -> bool:
        token_cookie = request.cookies.get("token_cookie")
        if not token_cookie:
            raise TokenMissingException("Token not provided")

        try:
            jwks = await self._token_verifier.get_jwks()
            claims = jwt.decode(token_cookie, jwks)
            claims.validate()
            return True
        except TokenVerifierException as e:
            raise OAuthServiceUnavailableException(f"Error requesting oauth service: {e}")
        except JoseError as e:
            raise TokenExpiredException(f"Invalid or expired token: {e}")

    def remove_token_cookie(self, request: Request, response: Response) -> Response:
        token_cookie = request.cookies.get("token_cookie")
        if not token_cookie:
            return response

        response.delete_cookie(key="token_cookie")
        return response

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_fixed(2),
        retry=retry_if_exception_type(OAuthError)
    )
    async def get_id_token(self, request: Request) -> str:
        try:
            token = await self.oauth.auth0.authorize_access_token(request)
            id_token = token.get("id_token")

            if not id_token:
                raise TokenMissingException("Access token not found")
            return id_token
        except OAuthError as e:
            raise OAuthServiceUnavailableException(f"Error fetching ID token: {e}")

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_fixed(2),
        retry=retry_if_exception_type(OAuthError)
    )
    async def authorize_access(self, request: Request) -> RedirectResponse:
        try:
            redirect_uri = request.url_for("callback")
            return await self.oauth.auth0.authorize_redirect(request, redirect_uri)
        except OAuthError as e:
            raise OAuthServiceUnavailableException(f"OAuth error during redirect: {e}")


def get_oauth_service(request: Request) -> OAuthManager:
    return request.app.state.oauth_service
