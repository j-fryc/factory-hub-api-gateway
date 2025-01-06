import httpx
from tenacity import retry, stop_after_attempt, retry_if_exception_type, wait_fixed


class TokenVerifierException(Exception):
    pass


class TokenVerifier:
    def __init__(self, domain: str):
        self.jwks_url = f"https://{domain}/.well-known/jwks.json"

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_fixed(2),
        retry=retry_if_exception_type((httpx.RequestError, httpx.HTTPStatusError))
    )
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
