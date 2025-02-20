from abc import ABC, abstractmethod
from typing import Dict

from fastapi import HTTPException

from app.config import Settings
from app.utils.api_layer_request_handler import ApiLayerRequestHandler
from app.utils.request_exceptions import BadRequestException, ServiceUnavailableException, BaseApiException


class BaseManager(ABC):
    def __init__(self, settings: Settings):
        self.request_handler = ApiLayerRequestHandler()
        self._settings = settings

    async def _send_request(self, method: str, endpoint: str, params=None, content=None) -> Dict | None:
        try:
            return await self.request_handler.make_request(
                method=method,
                endpoint=endpoint,
                params=params,
                content=content
            )
        except BadRequestException as e:
            raise HTTPException(status_code=400, detail=str(e))
        except (ServiceUnavailableException, BaseApiException):
            raise HTTPException(status_code=500, detail="Service unavailable")

    @property
    @abstractmethod
    def _api_endpoint(self) -> str:
        ...
