# -*- coding: utf-8 -*-
# * Authors:
#       * TJEBBES Gaston <g.t@majerti.fr>
#       * Arezki Feth <f.a@majerti.fr>;
#       * Miotte Julien <j.m@majerti.fr>;
import pytest

DEFAULT_URI = 'sqlite://'
DEFAULT_SETTINGS = {
    'oidc.require_ssl': 'false',
    'oidc.issuer_url': 'http://myoidc/oidc/',
    'oidc.salt': 'salt',
    'session.longtimeout': 2,
    'session.type': 'memory',
    'session.lock_dir': '/tmp',
    'session.webtest_varname': 'session',
    'pyramid.includes': '\npyramid_tm\npyramid_debugtoolbar\npyramid_chameleon\
\npyramid_layout\njs.deform'
}


DEFAULT_USER = {
    'login': 'admin',
    'firstname': 'admin',
    'lastname': 'admin',
    'email': 'admin@admin.fr',
}


def pytest_addoption(parser):
    parser.addoption('--sql-url', default=DEFAULT_URI,
                     help='SQLAlchemy Database URL')
    parser.addoption('--sql-echo', default=False, action='store_true',
                     help='Echo SQL statements to console')


def pytest_configure(config):
    pass
    # DatabaseTestCase.db_uri = config.getoption('sql_url')


@pytest.fixture(scope='session')
def settings():
    return DEFAULT_SETTINGS


@pytest.fixture(scope='session')
def registry(settings):
    from pyramid.registry import Registry
    registry = Registry()
    registry.settings = settings
    return registry


@pytest.fixture(scope='session')
def connection(settings, request):
    from sqlalchemy import create_engine
    from autonomie_base.models.base import (
        DBSESSION,
        DBBASE,
    )
    from autonomie.models.user import User
    print(User)
    from autonomie_oidc_provider import models
    print(models)

    engine = create_engine(
        request.config.option.sql_url,
        echo=request.config.option.sql_echo
    )

    if engine.dialect.name == 'sqlite':
        engine.execute('PRAGMA foreign_keys = ON')
    connection = engine.connect()
    DBSESSION.registry.clear()
    DBSESSION.configure(bind=connection)
    DBBASE.metadata.bind = engine
    return connection


@pytest.fixture(scope='session')
def content(connection, settings):
    from autonomie_base.models.base import DBBASE
    DBBASE.metadata.drop_all(connection.engine)
    DBBASE.metadata.create_all(connection.engine)


@pytest.fixture
def sql_session(content, connection, request):
    """Provide a configured SQLAlchemy session running within a transaction.
    You can use the --sql-url commandline option to specify the SQL backend to
    use. The default configuration will use an in-memory SQLite database.
    You can also use the --sql-echo option to enable logging of all SQL
    statements to the console.
    """
    # SQL is already configured, so make sure it is not run again which would
    # result in a second connection.
    from transaction import abort
    trans = connection.begin()
    request.addfinalizer(trans.rollback)
    request.addfinalizer(abort)
    from autonomie_base.models.base import DBSESSION
    return DBSESSION()


@pytest.fixture
def config(settings):
    from autonomie_oidc_provider import base_configure
    config = base_configure(None, **settings)
    return config


@pytest.fixture
def app(config, request, monkeypatch):
    app = config.make_wsgi_app()
    from webtest import TestApp

    if 'user' in request.keywords:
        print("USer in request.keywords")
        login = request.keywords['user'].args[0]
        monkeypatch.setattr(
            "pyramid.authentication."
            "SessionAuthenticationPolicy.unauthenticated_userid",
            lambda self, req: login
        )

    return TestApp(app)


@pytest.fixture
def oidc_client(sql_session):
    from autonomie_oidc_provider.models import OidcClient
    client = OidcClient(
        name='Test client',
        scopes='openid profile',
        cert_salt="123456",
    )
    client.client_secret = "client_secret_passphrase"
    sql_session.add(client)
    sql_session.flush()
    return client


@pytest.fixture
def oidc_redirect_uri(sql_session, oidc_client):
    from autonomie_oidc_provider.models import OidcRedirectUri
    uri = OidcRedirectUri(
        client=oidc_client,
        uri="http://test.com",
    )
    uri.client_id = oidc_client.id
    sql_session.add(uri)
    sql_session.flush()
    return uri


@pytest.fixture
def user(sql_session):
    from autonomie.models.user import User
    user = User(**DEFAULT_USER)
    user.set_password('o')
    sql_session.add(user)
    sql_session.flush()
    return user


@pytest.fixture
def oidc_code(sql_session, oidc_client, user, oidc_redirect_uri):
    from autonomie_oidc_provider.models import OidcCode
    code = OidcCode(
        client=oidc_client,
        user_id=user.id,
        uri=oidc_redirect_uri.uri,
        scopes='openid',
    )
    code.nonce = "Nonce value"
    sql_session.add(code)
    sql_session.flush()
    return code


@pytest.fixture
def oidc_token(sql_session, oidc_client, user):
    from autonomie_oidc_provider.models import OidcToken
    token = OidcToken(oidc_client, user.id)
    sql_session.add(token)
    sql_session.flush()
    return token
