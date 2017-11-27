# -*- coding: utf-8 -*-
# * Authors:
#       * TJEBBES Gaston <g.t@majerti.fr>
#       * Arezki Feth <f.a@majerti.fr>;
#       * Miotte Julien <j.m@majerti.fr>;
import pytest


def test_oidc_settings(registry, settings):
    from autonomie_oidc_provider.util import oidc_settings

    assert oidc_settings(settings, "require_ssl") == False
    assert oidc_settings(settings, "notasetting", "default") == "default"
    assert oidc_settings(settings, "notasetting") is None

    assert "require_ssl" in oidc_settings(settings)


def test_get_client_credentials():
    from autonomie_oidc_provider.util import get_client_credentials
    from autonomie_oidc_provider.exceptions import (
        InvalidRequest,
        InvalidCredentials,
    )
    from pyramid.testing import DummyRequest

    req = DummyRequest(headers={"Authorization": "Basic dG90bzp0YXRh"})
    assert get_client_credentials(req) == (u"toto", u"tata")

    req = DummyRequest(headers={"authorization": "Basic dG90bzp0YXRh"})
    assert get_client_credentials(req) == (u"toto", u"tata")

    req = DummyRequest(post={'client_id': u'toto', 'client_secret': u"tata"})
    assert get_client_credentials(req) == (u"toto", u"tata")

    req = DummyRequest(headers={"Bad Header": "Basic dG90bzp0YXRh"})
    with pytest.raises(InvalidRequest):
        get_client_credentials(req)

    req = DummyRequest(headers={"Authorization": "Customauth dG90bzp0YXRh"})
    with pytest.raises(InvalidCredentials):
        get_client_credentials(req)

    req = DummyRequest(headers={"Authorization": "Basic dG90bzp0YXRh OOO"})
    with pytest.raises(InvalidCredentials):
        get_client_credentials(req)


def test_get_access_token():
    from autonomie_oidc_provider.util import get_access_token

    from autonomie_oidc_provider.exceptions import (
        InvalidRequest,
        InvalidCredentials,
    )
    from pyramid.testing import DummyRequest

    req = DummyRequest(headers={"Authorization": "Bearer mybearertoken"})
    assert get_access_token(req) == u"mybearertoken"

    req = DummyRequest(headers={"authorization": "Bearer mybearertoken"})
    assert get_access_token(req) == u"mybearertoken"

    req = DummyRequest(headers={"notgoodheader": "Bearer mybearertoken"})
    with pytest.raises(InvalidRequest):
        get_access_token(req)

    req = DummyRequest(headers={"Authorization": "Bearer mybearertoken oo"})
    with pytest.raises(InvalidCredentials):
        get_access_token(req)

    req = DummyRequest(headers={"Authorization": "customformat mytoken"})
    with pytest.raises(InvalidCredentials):
        get_access_token(req)
