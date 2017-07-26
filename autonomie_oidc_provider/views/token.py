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
from autonomie.models.user import User
from autonomie_oidc_provider.exceptions import (
    InvalidCredentials,
    # UnauthorizedClient,
)
from autonomie_oidc_provider.util import get_client_credentials
from autonomie_oidc_provider.views import require_ssl
from autonomie_oidc_provider.models import (
    get_client_by_client_id,
    get_code_by_client_id,
    OidcToken,
    OidcIdToken,
)


logger = logging.getLogger(__name__)


class Scope(object):
    key = None
    attributes = ()

    def produce(self, user_object):
        res = {}
        for label, data_key in self.attributes:
            if data_key:
                res[label] = getattr(user_object, data_key, '')
            else:
                # Not implemented
                res[label] = ''
        return res


class OpenIdScope(Scope):
    key = 'openid'
    attributes = (
        ('user_id', 'id'),
    )


class ProfileScope(Scope):
    key = 'profile'
    attributes = (
        ('name', 'label'),
        ('firstname', 'firstname'),
        ('lastname', 'lastname'),
        ('email', 'email'),
        ('login', 'login'),
        ('groups', 'groups'),
    )


def collect_claims(user_id, scopes):
    """
    Collect the claims described by the requested scopes for the given user_id

    :param int user_id: The id of the user
    :param list scopes: The list of scopes we want to collect claims for
    :returns: The claims
    :rtype: dict
    """
    result = {}
    user = User.get(user_id)
    for scope in scopes:
        if scope == 'profile':
            factory = ProfileScope()
            result.update(factory.produce(user))
    return result


def handle_authcode_token(request, client, code, claims):
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

    result = token.__json__(request)
    result['id_token'] = id_token.__jwt__(request, claims)

    if 'state' in request.POST:
        result['state'] = request.POST['state']

    return result


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

    The view returns a JWT containing
    """
    try:
        client_id, client_secret = get_client_credentials(request)
    except KeyError:
        logger.exception("Invalid client authentication")
        return {
            'error': "invalid_request",
            "error_description": "Missing Authentication headers"
        }
    except InvalidCredentials:
        logger.exception("Invalid client authentication")
        return {
            'error': "invalid_request",
            "error_description": "Invalid Authentication headers"
        }

    # Client
    # Check secret
    # Check params (grant_type ...)
    # Check code
    # Check scope
    # Check redirect_uri
    # Issue token ...
    client = get_client_by_client_id(client_id)
    if client is None:
        logger.error("Invalid oidc client : %s", client_id)
        return {'error': "invalid_client"}
    elif not client.check_secret(client_secret):
        logger.warn("Invalid oidc client_secret : %s", client_secret)
        return {'error': "unauthorized_client"}

    grant_type = request.POST.get('grant_type')
    if grant_type != 'authorization_code':
        logger.warn("Invalid grant type : %s", grant_type)
        return {'error': "unsupported_grant_type"}

    logger.debug("POST Params : %s" % request.POST)

    code = request.POST.get('code')
    if code is not None:
        code = get_code_by_client_id(client.id, code)

    if code is None:
        logger.warn("Wrong auth code provided")
        return {'error': "invalid_grant"}

    redirect_uri = request.POST.get('redirect_uri')
    redirect_uri = unquote(redirect_uri)

    if redirect_uri is None or code.uri != redirect_uri:
        logger.error(
            "Provided redirect uri {0} doesn't match the "
            "expected one {1}".format(redirect_uri, code.uri)
        )
        return {
            'error': "invalid_grant",
            'error_description': "Invalid redirect_uri parameter"
        }

    # FIXME : enhance the scope stuff
    scope = request.POST.get('scope')
    if scope is not None:
        scopes = scope.split(' ')
        print(scopes)
        print(client.scopes)
        if 'openid' not in scopes or not client.check_scope(scopes):
            logger.error("Invalid list of requested scopes : %s", scopes)
            return {
                'error': 'invalid_request',
                'error_description': "Invalid scope parameter"
            }
    else:
        scopes = ['openid']

    claims = collect_claims(code.user_id, scopes)

    resp = handle_authcode_token(request, client, code, claims)
    return resp


def includeme(config):
    config.add_view(
        token_view,
        route_name='/token',
        renderer='json',
        permission=NO_PERMISSION_REQUIRED,
        request_method='POST',
    )
