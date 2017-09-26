# -*- coding: utf-8 -*-
# * Authors:
#       * TJEBBES Gaston <g.t@majerti.fr>
#       * Arezki Feth <f.a@majerti.fr>;
#       * Miotte Julien <j.m@majerti.fr>;
import logging
from six.moves.urllib.parse import (
    urlparse,
    parse_qsl,
    ParseResult,
    urlencode,
    unquote,
)
from pyramid.httpexceptions import (
    HTTPFound,
    HTTPBadRequest,
)
from pyramid.security import authenticated_userid

from autonomie_base.models.base import DBSESSION
from autonomie.models.user import User
from autonomie_oidc_provider.exceptions import InvalidRequest
from autonomie_oidc_provider.models import (
    get_client_by_client_id,
    OidcCode,
    OidcRedirectUri,
)
from autonomie_oidc_provider.views import require_ssl


logger = logging.getLogger(__name__)


def raise_authentication_error(
    redirection_uri, error, description=None, state=None
):
    """
    Raise an authentication error in case of existing redirection uri

    http://openid.net/specs/openid-connect-core-1_0.html#AuthError
    https://tools.ietf.org/html/rfc6749#section-4.1.2.1

    :param obj request: The request object
    :param str error: The error code
    :param str description: The optionnal description
    :param str state: The state passed by the client
    """
    url = urlparse(redirection_uri)
    query_params = {"error": error}

    if state is not None:
        query_params['state'] = state

    if description is not None:
        query_params['error_description'] = description

    url = url._replace(query=urlencode(query_params))
    raise HTTPFound(url=url)


def get_redirection_uri(redirect_uri, client):
    """
    Retrieve the OidcRedirectUri object associated to the given redirect_uri
    Ensure it belongs to the given client

    :param str redirect_uri: The redirect uri given in the parameters
    :param obj client: OidcClient instance
    :returns: A OidcRedirectUri instance or None
    :rtype: obj
    """
    redirect_uri = unquote(redirect_uri)
    if redirect_uri is None:
        result = None
    else:
        query = OidcRedirectUri.query()
        query = query.filter_by(uri=redirect_uri)
        query = query.filter_by(client_id=client.id)
        result = query.first()
    return result


def handle_authcode(request, client, redirection_uri, state=None, nonce=None):
    """
    Handle the authorization code first step redirection (redirect the browser
    with the authcode embeded in the url)

    :param obj request: The Pyramid request
    :param obj client: The OidcClient instance
    :param obj redirection_uri: The OidcRedirectUri instance
    :param str state: The state initially transmitted by the Resource Consumer
    (RC)
    :param str nonce: The nonce initially transmitted by the Resource Consumer
    (RC) (cross-request token)

    :returns: A HTTPFound instance
    """
    logger.debug("Handling the creation of an auth code")
    db = DBSESSION()
    parts = urlparse(redirection_uri.uri)
    qparams = dict(parse_qsl(parts.query))

    user_login = authenticated_userid(request)
    user_id = User.query().filter_by(login=user_login).first().id
    auth_code = OidcCode(client, user_id, redirection_uri.uri)
    if nonce is not None:
        auth_code.nonce = nonce
    db.add(auth_code)
    db.flush()
    logger.debug("An auth_code has been added")
    logger.debug(auth_code)
    logger.debug(auth_code.id)

    qparams['code'] = auth_code.authcode
    if state is not None:
        qparams['state'] = state

    parts = ParseResult(
        parts.scheme,
        parts.netloc,
        parts.path,
        parts.params,
        urlencode(qparams),
        ''
    )
    return HTTPFound(location=parts.geturl())


@require_ssl
def authentication_view(request):
    """
    View handling authentication requests

    http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
    """
    client_id = request.params.get('client_id')
    client = get_client_by_client_id(client_id)

    if client is None:
        logger.error('Unknown client')
        return HTTPBadRequest(
            InvalidRequest(
                error_description='Invalid client credentials'
            )
        )
    redirect_uri = request.params.get('redirect_uri')
    redirection_uri = get_redirection_uri(redirect_uri, client)
    if redirection_uri is None:
        return HTTPBadRequest(
            InvalidRequest(
                error_description='Invalid redirect_uri parameter'
            )
        )

    resp = None
    response_type = request.params.get('response_type')
    state = request.params.get('state')
    nonce = request.params.get('nonce')

    if response_type == 'code':
        resp = handle_authcode(request, client, redirection_uri, state, nonce)
    else:
        resp = raise_authentication_error(
            redirect_uri,
            "unsupported_response_type",
            description="Only authorization code process is supported for now",
            state=state,
        )

    return resp


def includeme(config):
    """
    Add the authorization view
    """
    config.add_view(
        authentication_view,
        route_name='/authorize',
        permission='oauth',
    )
