# -*-coding:utf-8-*-
import logging
from pyramid.httpexceptions import HTTPBadRequest
import json

from autonomie_base.utils.ascii import (
    force_ascii,
)
from autonomie_oidc_provider.exceptions import InvalidRequest
from autonomie_oidc_provider.util import oidc_settings


logger = logging.getLogger(__name__)


def require_ssl(handler):
    """
    This check should be taken care of via the authorization policy, but in
    case someone has configured a different policy, check again. HTTPS is
    required for all Oauth2 authenticated requests to ensure the security of
    client credentials and authorization tokens.
    """
    def wrapped(request):
        require_ssl = oidc_settings(
            request.registry.settings,
            key='require_ssl',
            default=True
        )
        if request.scheme != 'https' and require_ssl:
            logger.info(
                'rejected request due to unsupported scheme: %s'
                % request.scheme
            )
            return HTTPBadRequest(InvalidRequest(
                error_description='Oauth2 requires all requests'
                                  ' to be made via HTTPS.'))
        return handler(request)
    return wrapped


def http_error(request, exception, in_headers=False):
    """
    Return a pyramid http error given an exception instance

    :param obj exception: An exception inheriting from
    exceptions.BaseOauth2Error
    :param bool in_headers: Should we return the rror through the
    WWW-Authenticate header ?

    :returns: A Pyramid Response object
    """
    error = exception.datas['error']
    error_description = exception.datas['error_description']
    url_params = {
        'error': force_ascii(error),
        'error_description': force_ascii(error_description),
    }
    if 'state' in request.params:
        url_params['state'] = request.params['state']

    headers = [
        (
            "Location",
            request.current_route_url(_query=url_params)
        )
    ]
    return exception.response_class(headers=headers)


def http_json_error(request, exception, in_headers=False):
    """
    Return a pyramid http error in json format given an exception instance
    :param obj exception: An exception inheriting from
    exceptions.BaseOauth2Error
    :param bool in_headers: Should we return the rror through the
    WWW-Authenticate header ?
    :returns: A Pyramid Response object
    """
    if in_headers:
        error = exception.datas['error']
        error_description = exception.datas['error_description']
        headers = [
            (
                'WWW-Authenticate',
                'error=%s,error_description=%s' % (
                    force_ascii(error), force_ascii(error_description)
                )
            )
        ]
        return exception.response_class(headers=headers)
    else:
        resp = exception.response_class()
        resp.content_type = 'application/json'
        resp.body = json.dumps(exception.datas)
        return resp
