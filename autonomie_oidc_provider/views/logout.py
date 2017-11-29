# -*- coding: utf-8 -*-
# * Authors:
#       * TJEBBES Gaston <g.t@majerti.fr>
#       * Arezki Feth <f.a@majerti.fr>;
#       * Miotte Julien <j.m@majerti.fr>;
"""
Logout view
"""
import logging

from pyramid.security import (
    NO_PERMISSION_REQUIRED,
    forget,
)
from pyramid.httpexceptions import HTTPFound
from autonomie_oidc_provider.util import (
    add_get_params,
)


logger = logging.getLogger(__name__)


def logout_view(request):
    """
    Handle a basic logout of the current connected user

    http://openid.net/specs/openid-connect-session-1_0.html

    The request CAN contain the following parameters

        id_token_hint

            An id token corresponding to the user's auth, the audience of the
            token should include the current server

        post_logout_redirect_uri

            The uri to which we should redirect after logout

        state

            The state to be persisted if a redirect is also asked
    """
    # TODO : add a confirmation form for logout
    # TODO : add support for id_token_hint parameter
    redirect_uri = request.params.get('post_logout_redirect_uri', None)
    if redirect_uri is not None:
        state = request.params.get('state', None)
        if state is not None:
            redirect_uri = add_get_params(redirect_uri, {'state': state})

    forget(request)
    request.response.delete_cookie("remember_me")
    if redirect_uri:
        return HTTPFound(redirect_uri)

    return dict(
        message=u"Vous avez été déconnecté",
    )


def includeme(config):
    config.add_view(
        logout_view,
        route_name='/logout',
        permission=NO_PERMISSION_REQUIRED,
        renderer="autonomie_oidc_provider:templates/logout.pt",
        layout="login"
    )
