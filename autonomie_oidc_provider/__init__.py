#-*-coding:utf-8-*-
from pyramid.config import Configurator
from pyramid.authorization import ACLAuthorizationPolicy
from pyramid.authentication import SessionAuthenticationPolicy
from sqlalchemy import engine_from_config

from autonomie.utils.session import get_session_factory
from autonomie_base.models.initialize import initialize_sql

from autonomie_oidc_provider.security import RootFactory


def base_configure(global_config, **settings):
    session_factory = get_session_factory(settings)
    config = Configurator(
        settings=settings,
        authentication_policy=SessionAuthenticationPolicy(),
        authorization_policy=ACLAuthorizationPolicy(),
        session_factory=session_factory,
    )
    config._set_root_factory(RootFactory)
    # All views not specifying permission explicitly need admin perm (to avoid
    # security leaks)
    config.set_default_permission('admin')
    config.add_static_view(
        'static',
        'autonomie:static/'
    )
    config.include('.models')
    config.include('.routes')
    config.include('.subscribers')
    config.include('.layout')
    config.include('.views.login')
    config.include('.views.authorize')
    config.include('.views.token')
    config.include('.views.userinfo')
    config.include('.views.logout')

    config.include('.views.index')
    return config


def main(global_config, **settings):
    """ This function returns a Pyramid WSGI application.
    """
    config = base_configure(global_config, **settings)
    engine = engine_from_config(settings, "sqlalchemy.")
    initialize_sql(engine)
    return config.make_wsgi_app()


def includeme(config):
    """
    Autonomie inclusion hook point
    """
    from autonomie_oidc_provider.models import *
