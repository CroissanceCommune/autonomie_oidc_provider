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
from pyramid.httpexceptions import HTTPUnauthorized

from autonomie_base.utils.ascii import (
    force_ascii,
)
from autonomie_oidc_provider.exceptions import (
    InvalidCredentials,
    InvalidRequest,
)
from autonomie_oidc_provider.util import get_access_token


logger = logging.getLogger(__name__)


def unauthorized_response(exception):
    """
    Return a 401 error filling headers with the datas described there :
        https://tools.ietf.org/html/rfc6750#section-3
    """
    print(force_ascii(u"error=%s,error_description=%s" % (
        exception.datas['error'],
        exception.datas['error_description'].replace('\n', '.'),
    ))
    )
    headers = [(
        "WWW-Authenticate",
        force_ascii(u"error=%s,error_description=%s" % (
            exception.datas['error'], exception.datas['error_description'],
        )),
    )]
    return HTTPUnauthorized(headers=headers)


def userinfo_view(request):
    """
    The userinfo view
    """
    try:
        token = get_access_token(request)
    except (InvalidRequest, InvalidCredentials) as exc:
        logger.exception(u"Error")
        return unauthorized_response(exc)


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
