class BaseApiException(Exception):
    pass


class ServiceUnavailableException(BaseApiException):
    pass


class BadRequestException(BaseApiException):
    pass
