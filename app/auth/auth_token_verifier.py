import httpx

from app.auth.auth_exceptions import TokenVerifierException


class TokenVerifier:
    def __init__(self, domain: str):
        self.jwks_url = f"https://{domain}/.well-known/jwks.json"

    async def get_jwks(self):
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(self.jwks_url)
                response.raise_for_status()
                return response.json()
        except httpx.RequestError as e:
            raise TokenVerifierException(f"Error fetching JWKS: {e}")
        except httpx.HTTPStatusError as e:
            raise TokenVerifierException(f"JWKS request failed with status {e.response.status_code}")
