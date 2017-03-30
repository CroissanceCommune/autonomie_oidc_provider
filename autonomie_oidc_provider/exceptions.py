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


class BaseOauth2Error(dict):
    error_name = None

    def __init__(self, **kw):
        dict.__init__(self)
        if kw:
            self.update(kw)
        self['error'] = self.error_name

        if 'error_description' not in self:
            self['error_description'] = self.__doc__


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


class InvalidToken(BaseOauth2Error):
    """
    The access token provided is expired, revoked, malformed, or
    invalid for other reasons.  The resource SHOULD respond with the
    HTTP 401 (Unauthorized) status code.  The client MAY request a new
    access token and retry the protected resource request.

    https://tools.ietf.org/html/rfc6749#section-3.1
    """
    error_name = 'invalid_token'
