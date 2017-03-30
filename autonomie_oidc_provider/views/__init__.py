#-*-coding:utf-8-*-
from pyramid.httpexceptions import HTTPBadRequest

from autonomie_oidc_provider.exceptions import InvalidRequest
from autonomie_oidc_provider.util import oidc_settings


def require_ssl(handler):
    """
    This check should be taken care of via the authorization policy, but in
    case someone has configured a different policy, check again. HTTPS is
    required for all Oauth2 authenticated requests to ensure the security of
    client credentials and authorization tokens.
    """
    def wrapped(request):
        if (request.scheme != 'https' and
                oidc_settings('require_ssl', default=True)):
            log.info('rejected request due to unsupported scheme: %s'
                     % request.scheme)
            return HTTPBadRequest(InvalidRequest(
                error_description='Oauth2 requires all requests'
                                  ' to be made via HTTPS.'))
        return handler(request)
    return wrapped

