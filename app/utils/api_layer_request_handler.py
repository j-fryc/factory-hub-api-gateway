from typing import Optional, Dict, Any

import httpx

from fastapi import Request
from app.utils.request_exceptions import (
    BaseApiException,
    ServiceUnavailableException,
    BadRequestException
)


class ApiLayerRequestHandler:
    def __init__(self):
        self._headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        self._exceptions_dict = {
            400: BadRequestException,
            500: ServiceUnavailableException,
            'default': BaseApiException
        }

    async def make_request(
            self,
            method: str,
            endpoint: str,
            params: Optional[Dict[str, Any]] = None,
            content: Optional[str] = None,
    ) -> Dict | None:
        async with httpx.AsyncClient() as client:
            try:
                response = await client.request(
                    method=method,
                    url=endpoint,
                    headers=self._headers,
                    params=params,
                    content=content,
                )
                response.raise_for_status()
                return response.json() if response.status_code != 204 else None
            except httpx.RequestError as e:
                raise self._exceptions_dict['default'](e)
            except httpx.HTTPStatusError as e:
                exception_to_rise = self._exceptions_dict.get(e.response.status_code)
                if exception_to_rise:
                    raise exception_to_rise(e)
                raise self._exceptions_dict['default'](e)


async def get_request_handler(request: Request) -> RequestHandler:
    return request.app.state.request_handler
