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
)
from pyramid.security import (
    authenticated_userid,
)

from autonomie_base.models.base import DBSESSION

from autonomie.models.user.login import Login

from autonomie_oidc_provider.exceptions import (
    InvalidRequest,
    InvalidScope,
    UnsupportedGrantType,
)
from autonomie_oidc_provider.models import (
    get_client_by_client_id,
    OidcCode,
    OidcRedirectUri,
)
from autonomie_oidc_provider.views import (
    require_ssl,
    http_error,
)


logger = logging.getLogger(__name__)


def raise_authentication_error(
    redirection_uri, exception, state=None, nonce=None
):
    """
    Raise an authentication error in case of existing redirection uri

    http://openid.net/specs/openid-connect-core-1_0.html#AuthError
    https://tools.ietf.org/html/rfc6749#section-4.1.2.1

    :param obj request: The request object
    :param obj exception: exception instance
    :param str state: The state passed by the client
    :param str nonce: The nonce passed by the client
    """
    url = urlparse(redirection_uri)
    query_params = exception.datas.copy()

    if state is not None:
        query_params['state'] = state

    if nonce is not None:
        query_params['nonce'] = nonce

    url = url._replace(query=urlencode(query_params))
    raise HTTPFound(url.geturl())


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


def handle_authcode(
    request, client, redirection_uri, scopes, state=None, nonce=None
):
    """
    Handle the authorization code first step redirection (redirect the browser
    with the authcode embeded in the url)

    :param obj request: The Pyramid request
    :param obj client: The OidcClient instance
    :param obj redirection_uri: The OidcRedirectUri instance
    :param str scopes: The scopes associated to this code
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
    user_id = Login.query().filter_by(login=user_login).first().user_id
    auth_code = OidcCode(client, user_id, redirection_uri.uri, scopes)
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


def validate_client(client_id):
    """
    Validate the provided client id and return it back

    :param str client_id: The provided client_id
    :returns: An OidcClient instance
    """
    client = get_client_by_client_id(client_id)
    if client is None:
        raise InvalidRequest(
            error_description='Invalid client credentials'
        )
    return client


def validate_redirect_uri(redirect_uri, client):
    """
    Validate the provided redirect_uri

    :param str redirect_uri: The redirect_uri passed through the request
    :param obj client: The associated client object
    :returns: A OidcRedirectUri instance
    """
    redirection_uri = get_redirection_uri(redirect_uri, client)
    if redirection_uri is None:
        raise InvalidRequest(
            error_description='Invalid client credentials'
        )
    return redirection_uri


def validate_scopes(scope_str, client):
    """
    Validate given scopes are valid
    http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest

    :param str scope_str: The space delimited list of requested scopes
    :param obj client: An OidcClient
    :returns: A space delimited list of scopes
    :rtype: str
    :raises: InvalidRequest if wrong scope
    """
    if scope_str is None or 'openid' not in scope_str:
        raise InvalidScope(
            error_description="Missing scope key"
        )
    scopes = scope_str.split(' ')
    return ' '.join(
        [scope for scope in scopes if scope in client.scopes.split(' ')]
    )


def validate_response_type(response_type):
    if response_type != 'code':
        raise UnsupportedGrantType(
            error_description="Only authorization code process is supported"
        )
    return response_type


@require_ssl
def authorize_view(request):
    """
    View handling authentication requests

    http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
    """
    logger.debug(u"Authorize view")
    client_id = request.params.get('client_id')
    try:
        client = validate_client(client_id)
    except InvalidRequest as exc:
        logger.exception("  - Invalid client_id")
        return http_error(request, exc)

    redirect_uri = request.params.get('redirect_uri')
    try:
        redirection_uri = validate_redirect_uri(redirect_uri, client)
    except InvalidRequest as exc:
        logger.exception("  - Invalid redirect_uri")
        return http_error(request, exc)

    resp = None
    state = request.params.get('state')
    nonce = request.params.get('nonce')

    scope = request.params.get('scope')
    try:
        scopes = validate_scopes(scope, client)
    except InvalidScope as exc:
        logger.exception("  - Invalid scope")
        return raise_authentication_error(
            redirect_uri,
            exc,
            state=state,
            nonce=nonce,
        )

    response_type = request.params.get('response_type')
    try:
        response_type = validate_response_type(response_type)
    except UnsupportedGrantType as exc:
        logger.exception("  - Invalid grant type")
        return raise_authentication_error(
            redirect_uri,
            exc,
            state=state,
            nonce=nonce,
        )

    resp = handle_authcode(
        request, client, redirection_uri, scopes, state, nonce
    )

    return resp


def includeme(config):
    """
    Add the authorize view
    """
    config.add_view(
        authorize_view,
        route_name='/authorize',
        permission='oauth',
    )
