# -*- coding: utf-8 -*-
# * Authors:
#       * TJEBBES Gaston <g.t@majerti.fr>
#       * Arezki Feth <f.a@majerti.fr>;
#       * Miotte Julien <j.m@majerti.fr>;
import logging

from pyramid.security import NO_PERMISSION_REQUIRED
from six.moves.urllib.parse import (
    unquote,
)

from autonomie_base.models.base import DBSESSION
from autonomie_oidc_provider.exceptions import (
    InvalidCredentials,
    InvalidRequest,
    InvalidClient,
    UnauthorizedClient,
)
from autonomie_oidc_provider.scope_consumer import (
    collect_claims,
)

from autonomie_oidc_provider.util import get_client_credentials
from autonomie_oidc_provider.views import (
    require_ssl,
    http_json_error,
)
from autonomie_oidc_provider.models import (
    get_client_by_client_id,
    get_code_by_client_id,
    OidcToken,
    OidcIdToken,
)


logger = logging.getLogger(__name__)


def get_claims(code, scopes):
    """
    Build the dict of claims to be returned to the client

    :param obj code: The Oidc authentication code used for token generation
    :param list scopes: List of scopes to be collected
    :returns: A dict of claims
    :rtype: dict
    """
    claims = collect_claims(code.user_id, scopes)
    if code.nonce is not None:
        claims['nonce'] = code.nonce

    return claims


def handle_authcode_token(request, client, code, claims, client_secret):
    """
    Handle the token response for authentication code request types

    Returns :

    {
        "access_token":"2YotnFZFEjr1zCsicMWpAA",
        "token_type":"Bearer",
        "expires_in":3600,
        "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",
        "id_token": <JWT representation of the id token>
    }

    :param obj client: A OidcClient
    :param obj code: A OidcCode
    :param dict claims: Claims queried by the given client
    :param str client_secret: The secret key used to authenticate (used for
    encryption)
    :returns: A dict to be used as json response
    :rtype: dict
    """
    token = OidcToken(client, code.user_id)
    DBSESSION().add(token)

    issuer = request.registry.settings.get('oidc.issuer_url')
    logger.debug("The current issuer url : %s" % issuer)

    id_token = OidcIdToken(
        issuer,
        client,
        code
    )
    DBSESSION().add(id_token)
    DBSESSION().flush()

    claims['at_hash'] = token.at_hash()

    result = token.__json__(request)
    logger.debug("Signing with %s" % client_secret)
    result['id_token'] = id_token.__jwt__(request, claims, client_secret)

    if 'state' in request.POST:
        result['state'] = request.POST['state']

    logger.debug("Returning the json datas : %s" % result)
    return result


def validate_client(client_id, client_secret):
    """
    Retrieve the client given a client id and validate it

    :param str client_id: The client id
    :param str client_secret: The client secret object

    :returns: A OidcClient instance
    :raises: InvalidClient
    :raises: UnauthorizedClient
    """
    client = get_client_by_client_id(client_id)
    if client is None:
        logger.error("Invalid oidc client : %s", client_id)
        raise InvalidClient(error_description=u"Unknown client")
    elif not client.check_secret(client_secret):
        logger.warn("Invalid oidc client_secret : %s", client_secret)
        raise UnauthorizedClient(error_description=u"Unknown client")

    return client


def validate_grant_type(grant_type):
    """
    Validate it's a supported grant type

    :param str grant_type: The asked grant_type
    :raises: InvalidCredentials
    """
    if grant_type != 'authorization_code':
        logger.warn("Invalid grant type : %s", grant_type)
        raise InvalidRequest(error_description="unsupported_grant_type")


def validate_code(code, client):
    """
    Retrieve an OidcCode instance

    :param str code: The auth code
    :param obj client: The OidcClient instance
    :returns: the OidcCode instance
    :raises: InvalidCredentials
    """
    if code is not None:
        code = get_code_by_client_id(client.id, code)

    if code is None:
        logger.warn("Wrong auth code provided")
        raise InvalidCredentials(error_description="Invalid auth code")
    return code


def validate_redirect_uri(redirect_uri, code):
    """
    Check the given redirect_uri

    :param str redirect_uri: redirect_uri found in the request params
    :param obj code: OidcCode instance
    :raises: InvalidCredentials
    """
    redirect_uri = unquote(redirect_uri)
    if redirect_uri is None or code.uri != redirect_uri:
        logger.error(
            "Provided redirect uri {0} doesn't match the "
            "expected one {1}".format(redirect_uri, code.uri)
        )
        raise InvalidCredentials(
            error_description="Invalid redirect_uri parameter"
        )
    return redirect_uri


def validate_scopes(scope, client):
    """
    Check the scopes are valid
    :param str scope: The scope string (space-delimited list)
    :param obj client: The OidcClient
    :returns: The scopes str list
    :raises: InvalidRequest
    """
    if scope is not None:
        scopes = scope.split(' ')
        if 'openid' not in scopes or not client.check_scope(scopes):
            logger.error("Invalid list of requested scopes : %s", scopes)
            raise InvalidRequest(
                error_description="Invalid scope parameter"
            )
    else:
        scopes = ['openid']
    return scopes


@require_ssl
def token_view(request):
    """
    Token endpoint :
        http://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint
        https://tools.ietf.org/html/rfc6749#section-3.2

    Calls to the token endpoint MUST contain :

        client_id

            The confidential client id

        client_secret

            The confidential client secret key

        redirect_uri

            The redirect_uri used on the step 1 of the Authorization code auth
            flow

        code

            The code issued by the auth endpoint on step 1

    Calls to the token endpoint CAN contain :

        state

            A persisted state variable

        scopes

            Scopes that should be associated with the token

    The view returns a JWT containing
    """
    try:
        client_id, client_secret = get_client_credentials(request)
    except InvalidRequest as exc:
        logger.exception("Invalid client authentication")
        return http_json_error(request, exc)
    except InvalidCredentials as exc:
        logger.exception("Invalid client authentication")
        return http_json_error(request, exc)

    # Client
    # Check secret
    # Check params (grant_type ...)
    # Check code
    # Check scope
    # Check redirect_uri
    # Issue token ...
    try:
        client = validate_client(client_id, client_secret)
    except InvalidClient as exc:
        return http_json_error(request, exc)

    grant_type = request.POST.get('grant_type')
    try:
        validate_grant_type(grant_type)
    except InvalidRequest as exc:
        return http_json_error(request, exc)

    logger.debug("POST Params : %s" % request.POST)

    auth_code = request.POST.get('code')

    try:
        code = validate_code(auth_code, client)
    except InvalidCredentials as exc:
        return http_json_error(request, exc)

    redirect_uri = request.POST.get('redirect_uri')

    try:
        redirect_uri = validate_redirect_uri(redirect_uri, code)
    except InvalidCredentials as exc:
        return http_json_error(request, exc)

    # FIXME : enhance the scope stuff
    scope = request.POST.get('scope')
    try:
        scopes = validate_scopes(scope, client)
    except InvalidRequest as exc:
        return http_json_error(request, exc)

    claims = get_claims(code, scopes)
    resp = handle_authcode_token(request, client, code, claims, client_secret)
    return resp


def includeme(config):
    config.add_view(
        token_view,
        route_name='/token',
        renderer='json',
        permission=NO_PERMISSION_REQUIRED,
        request_method='POST',
    )
