#
# Copyright (c) Elliot Peele <elliot@bentlogic.net>
#
# This program is distributed under the terms of the MIT License as found
# in a file called LICENSE. If it is not present, the license
# is always available at http://www.opensource.org/licenses/mit-license.php.
#
# This program is distributed in the hope that it will be useful, but
# without any warrenty; without even the implied warranty of merchantability
# or fitness for a particular purpose. See the MIT License for full details.
#

from pyramid.httpexceptions import (
    HTTPUnauthorized,
    HTTPBadRequest,
    HTTPForbidden,
)


class BaseOauth2Error(Exception):
    error_name = None
    response_class = HTTPBadRequest

    def __init__(self, **kw):
        self.datas = {}
        if kw:
            self.datas.update(kw)
        self.datas['error'] = self.error_name

        if 'error_description' not in self.datas:
            self.datas['error_description'] = self.__doc__


class InvalidRequest(BaseOauth2Error):
    """
    Invalid request, some parameters are missing see the following specs for
    more infos

    http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
    https://tools.ietf.org/html/rfc6749#section-4.1.2.1
    """
    error_name = 'invalid_request'


class InvalidClient(BaseOauth2Error):
    """
    The provided authorization grant is invalid, expired, revoked, or
    was issued to another cilent.

    https://tools.ietf.org/html/rfc6749#section-5.2
    """
    error_name = 'invalid_client'
    response_class = HTTPUnauthorized


class UnauthorizedClient(BaseOauth2Error):
    """
    The authenticated user is not authorized to use this authorization
    grant type.

    https://tools.ietf.org/html/rfc6749#section-5.2
    """
    error_name = 'unauthorized_client'


class UnsupportedGrantType(BaseOauth2Error):
    """
    The authorizaiton grant type is not supported by the authorization
    server.

    https://tools.ietf.org/html/rfc6749#section-5.2
    """
    error_name = 'unsupported_grant_type'


class InvalidScope(BaseOauth2Error):
    """
    The requested scope is invalid, unknown, malformed, or
    exceeds the scope granted by the resource owner.
    """
    error_name = "invalid_scope"


class InvalidToken(BaseOauth2Error):
    """
    The access token provided is expired, revoked, malformed, or
    invalid for other reasons.  The resource SHOULD respond with the
    HTTP 401 (Unauthorized) status code.  The client MAY request a new
    access token and retry the protected resource request.

    https://tools.ietf.org/html/rfc6749#section-3.1
    """
    error_name = 'invalid_token'
    response_class = HTTPUnauthorized


class InsufficientScope(BaseOauth2Error):
    """
    The request requires higher privileges than provided by the
    access token.  The resource server SHOULD respond with the HTTP
    403 (Forbidden) status code and MAY include the "scope"
    attribute with the scope necessary to access the protected
    resource.
    """
    error_name = 'insufficient_scope'
    response_class = HTTPForbidden


class InvalidCredentials(BaseOauth2Error):
    """
    The credentials provided in the request header are not handled by this Open
    id connect provider
    Only Basic authentication headers are handled
    """
    error_name = "invalid_grant"
    response_class = HTTPForbidden
