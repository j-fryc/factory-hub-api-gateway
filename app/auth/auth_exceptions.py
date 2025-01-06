class TokenVerifierException(Exception):
    pass


class OAuthManagerException(Exception):
    pass


class OAuthServiceUnavailableException(OAuthManagerException):
    pass


class TokenExpiredException(OAuthManagerException):
    pass


class TokenMissingException(OAuthManagerException):
    pass