# -*- coding: utf-8 -*-
# * Authors:
#       * TJEBBES Gaston <g.t@majerti.fr>
#       * Arezki Feth <f.a@majerti.fr>;
#       * Miotte Julien <j.m@majerti.fr>;
from pyramid.security import NO_PERMISSION_REQUIRED


def index_view(request):
    """
    Simple index view

    :param obj request: The Pyramid request
    """
    path = request.route_path(
        '/authorize',
        _query={
            'response_type': 'code',
            'scope': 'openid',
            'redirect_uri': 'http://gaston:1234',
            'client_id': '7dd49f6f72f04e10c1d600d741a2be0d10e83a43b7fa790003649076fa606c6e',
        }
    )
    return dict(path=path)


def includeme(config):
    """
    Add the index view
    """
    config.add_view(
        index_view,
        route_name="/",
        layout="formlayout",
        permission=NO_PERMISSION_REQUIRED,
        renderer="autonomie_oidc_provider:templates/index.pt",
    )
