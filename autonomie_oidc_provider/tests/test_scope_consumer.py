# -*- coding: utf-8 -*-
# * Authors:
#       * TJEBBES Gaston <g.t@majerti.fr>
#       * Arezki Feth <f.a@majerti.fr>;
#       * Miotte Julien <j.m@majerti.fr>;
import pytest
from autonomie_oidc_provider import scope_consumer


class Dummy:
    def __init__(self, **kw):
        self.__dict__.update(kw)


@pytest.fixture
def login():
    return Dummy(
        login="login"
    )

@pytest.fixture
def user(login):
    return Dummy(
        firstname="firstname",
        lastname="lastname",
        email="email@mail.fr",
        login=login
    )


def test_profile_scope(user):
    consumer = scope_consumer.ProfileScope()
    claims = consumer.produce(user)

    assert claims['email'] == user.email
    assert claims['login'] == 'login'
