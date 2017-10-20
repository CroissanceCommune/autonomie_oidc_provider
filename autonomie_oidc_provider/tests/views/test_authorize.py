# -*- coding: utf-8 -*-
# * Authors:
#       * TJEBBES Gaston <g.t@majerti.fr>
#       * Arezki Feth <f.a@majerti.fr>;
#       * Miotte Julien <j.m@majerti.fr>;
import pytest
import urlparse


def get_url_params_dict(url):
    parsed = urlparse.urlparse(url)
    return urlparse.parse_qs(parsed.query)


def test_validate_client(oidc_client):
    client_id = oidc_client.client_id
    from autonomie_oidc_provider.views.authorize import validate_client
    from autonomie_oidc_provider.exceptions import InvalidRequest
    assert validate_client(client_id) == oidc_client

    with pytest.raises(InvalidRequest):
        validate_client("okokokokoyfvuedhduehiudhi")


def test_validate_redirect_uri(oidc_client, oidc_redirect_uri):
    from autonomie_oidc_provider.views.authorize import validate_redirect_uri
    from autonomie_oidc_provider.exceptions import InvalidRequest
    assert validate_redirect_uri(
        oidc_redirect_uri.uri,
        oidc_client) == oidc_redirect_uri

    with pytest.raises(InvalidRequest):
        validate_redirect_uri("http://example.com", oidc_client)


def test_view_redirect(app, oidc_client, oidc_redirect_uri):
    res = app.get('/authorize')
    assert res.status_int == 302


@pytest.mark.user('admin')
def test_view_authenticated(app, user, oidc_client, oidc_redirect_uri):

    # Ok Query
    res = app.get(
        '/authorize?client_id=%s&response_type=code&redirect_uri=%s&state=toto&scope=openid' % (
            oidc_client.client_id,
            oidc_redirect_uri.uri,
        )
    )
    assert res.status_int == 302
    redirect = res.headers['Location']
    print(redirect)
    assert redirect.startswith(oidc_redirect_uri.uri)
    params = get_url_params_dict(redirect)
    assert 'code' in params
    assert params['state'] == ["toto"]

    # No params given
    res = app.get('/authorize', status=400)
    assert res.status_int == 400

    res = app.get('/authorize?client_id=%s&response_type=code', status=400)
    assert res.status_int == 400

    # client_id is wrong
    res = app.get(
        '/authorize?client_id=ooo&response_type=code&redirect_uri=%s' % (
        oidc_redirect_uri.uri,
    ), status=400)

    assert res.status_int == 400

    # Missing scope
    res = app.get(
        '/authorize?client_id=%s&response_type=code&redirect_uri=%s&state=toto' % (
            oidc_client.client_id,
            oidc_redirect_uri.uri,
        ),
        status=302
    )
    assert res.status_int == 302
    redirect = res.headers['Location']
    assert redirect.startswith(oidc_redirect_uri.uri)
    params = get_url_params_dict(redirect)
    assert params['error'] == ['invalid_scope']

    # response_type is not supported
    res = app.get(
        '/authorize?client_id=%s&response_type=implicit&redirect_uri=%s&state=toto&scope=openid' % (
            oidc_client.client_id,
            oidc_redirect_uri.uri,
        ),
    )
    assert res.status_int == 302
    redirect = res.headers['Location']
    assert redirect.startswith(oidc_redirect_uri.uri)
    params = get_url_params_dict(redirect)
    assert params['error'] == ['unsupported_grant_type']
    assert params['state'] == ['toto']
