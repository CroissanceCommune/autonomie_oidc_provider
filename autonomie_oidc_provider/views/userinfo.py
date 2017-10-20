# -*- coding: utf-8 -*-
# * Authors:
#       * TJEBBES Gaston <g.t@majerti.fr>
#       * Arezki Feth <f.a@majerti.fr>;
#       * Miotte Julien <j.m@majerti.fr>;
"""
User info endpoint as described in :
    http://openid.net/specs/openid-connect-core-1_0.html#UserInfo
"""
import logging
from pyramid.security import NO_PERMISSION_REQUIRED

from autonomie_oidc_provider.exceptions import (
    InvalidCredentials,
    InvalidRequest,
    InvalidToken,
)
from autonomie_oidc_provider.util import get_access_token
from autonomie_oidc_provider.models import OidcToken
from autonomie_oidc_provider.scope_consumer import (
    collect_claims,
)
from autonomie_oidc_provider.views import http_json_error


logger = logging.getLogger(__name__)


def validate_token(token_str):
    """
    Validate a bearer token trying to retrieve the associated OidcToken
    """
    token = OidcToken.find(token_str)
    if token is None:
        raise InvalidToken(error_description=u"Unknown token")

    if token.is_revoked():
        raise InvalidToken(error_description=u"Expired token")
    return token


def userinfo_view(request):
    """
    The userinfo view
    """
    logger.debug("Calling the userinfo_view")
    logger.debug("  + POST params")
    logger.debug(request.POST)
    logger.debug("  + GET params")
    logger.debug(request.GET)
    try:
        token = get_access_token(request)
    except (InvalidRequest, InvalidCredentials) as exc:
        logger.exception(u"Error")
        return http_json_error(request, exc)

    try:
        oidc_token = validate_token(token)
    except InvalidToken as exc:
        logger.exception(u"Invalid token")
        return http_json_error(request, exc)

    # Here the user is authenticated
    scopes = oidc_token.client.get_scopes()
    return collect_claims(oidc_token.user_id, scopes)


def includeme(config):
    """
    Add the authorization view
    """
    config.add_view(
        userinfo_view,
        route_name='/userinfo',
        renderer='json',
        permission=NO_PERMISSION_REQUIRED,
        request_method='POST',
    )
    config.add_view(
        userinfo_view,
        route_name='/userinfo',
        renderer='json',
        permission=NO_PERMISSION_REQUIRED,
        request_method='GET',
    )
