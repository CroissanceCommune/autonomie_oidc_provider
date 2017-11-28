# -*- coding: utf-8 -*-
# * Authors:
#       * TJEBBES Gaston <g.t@majerti.fr>
#       * Arezki Feth <f.a@majerti.fr>;
#       * Miotte Julien <j.m@majerti.fr>;
import pytest


def test_claims(oidc_code, user):
    from autonomie_oidc_provider.views.token import get_claims
    scopes = ['openid']
    result = get_claims(oidc_code, scopes)
    assert result['nonce'] == oidc_code.nonce
    assert result['sub'] == user.id


def test_handle_authcode_token(registry, oidc_client, oidc_code):
    from pyramid.testing import DummyRequest
    from jwkest.jws import (
        JWS,
        left_hash,
    )
    from jwkest.jwk import SYMKey

    from autonomie_oidc_provider.models import MAC
    from autonomie_oidc_provider.views.token import handle_authcode_token

    req = DummyRequest()
    req.registry = registry
    claims = {'login': 'testuser', 'firstname': 'Firstname'}
    result = handle_authcode_token(
        req,
        oidc_client,
        oidc_code,
        claims,
        oidc_client.client_secret,
    )
    assert "access_token" in result

    id_token = result['id_token']

    key = SYMKey(key=oidc_client.client_secret, alg=MAC)
    id_token_datas = JWS().verify_compact(id_token, keys=[key])

    assert id_token_datas['at_hash'] == left_hash(result['access_token'], MAC)
    assert 'iss' in id_token_datas
    assert id_token_datas['aud'] == oidc_client.client_id


def test_validate_client(oidc_client):
    from autonomie_oidc_provider.exceptions import (
        InvalidClient,
        UnauthorizedClient,
    )
    from autonomie_oidc_provider.views.token import validate_client

    with pytest.raises(InvalidClient):
        validate_client("wrong_client_id", "client_secret_passphrase")

    with pytest.raises(UnauthorizedClient):
        validate_client(oidc_client.client_id, "wrong secret")

    client = validate_client(oidc_client.client_id, "client_secret_passphrase")
    assert client == oidc_client


def test_validate_grant_type():
    from autonomie_oidc_provider.exceptions import InvalidRequest
    from autonomie_oidc_provider.views.token import validate_grant_type

    with pytest.raises(InvalidRequest):
        validate_grant_type('no good auth')

    validate_grant_type('authorization_code')


def test_validate_code(oidc_code, oidc_client):
    from autonomie_oidc_provider.exceptions import InvalidCredentials
    from autonomie_oidc_provider.views.token import validate_code

    validate_code(oidc_code.authcode, oidc_client)
    with pytest.raises(InvalidCredentials):
        validate_code("Bad code", oidc_client)



def test_validate_redirect_uri(oidc_redirect_uri, oidc_code):
    from autonomie_oidc_provider.exceptions import InvalidCredentials
    from autonomie_oidc_provider.views.token import validate_redirect_uri

    validate_redirect_uri(oidc_redirect_uri.uri, oidc_code)
    with pytest.raises(InvalidCredentials):
        validate_redirect_uri("http://malicious.com", oidc_code)


def test_validate_scopes(oidc_client):
    from autonomie_oidc_provider.exceptions import InvalidRequest
    from autonomie_oidc_provider.views.token import validate_scopes

    assert validate_scopes(None, oidc_client) == ['openid']

    with pytest.raises(InvalidRequest):
        validate_scopes("openid profile otherone", oidc_client)

    assert validate_scopes('openid profile', oidc_client) == [
        'openid', 'profile'
    ]


@pytest.mark.user('admin')
def test_token_view(app, user, oidc_client, oidc_code, oidc_redirect_uri):
    from base64 import b64encode
    headers = {
        "Authorization": "Basic %s" % (
            b64encode(
                "%s:%s" % (
                    oidc_client.client_id, "client_secret_passphrase"
                )
            )
        )
    }
    params = {
        'code': oidc_code.authcode,
        'redirect_uri': oidc_redirect_uri.uri,
        'grant_type': 'authorization_code',
        'scope': 'openid profile',
        "state": "should be persisted state",
    }

    res = app.post(
        "/token",
        headers=headers,
        params=params
    )
    assert 'access_token' in res.json

