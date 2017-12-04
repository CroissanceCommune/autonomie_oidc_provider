# -*- coding:utf-8 -*-

from autonomie_oidc_provider.config import SCOPES


def format_scope(scope):
    """
    Format a scope and returns its associated label

    :param str scope: DB format scope string
    :returns: A UI label
    """
    return dict(SCOPES).get(scope, scope)


def customize_tmpl_api():
    from autonomie.views.render_api import Api

    Api.format_scope = staticmethod(format_scope)


def includeme(config):
    config.include('.security')
    config.include('.views.client')
    customize_tmpl_api()
