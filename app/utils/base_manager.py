from fastapi import HTTPException

from app.utils.api_layer_request_handler import ApiLayerRequestHandler
from app.utils.request_exceptions import BadRequestException, ServiceUnavailableException, BaseApiException


class BaseManager:
    def __init__(self):
        self.request_handler = ApiLayerRequestHandler()

    async def _send_request(self, method: str, endpoint: str, params=None, content=None):
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