# -*- coding: utf-8 -*-
# * Authors:
#       * TJEBBES Gaston <g.t@majerti.fr>
#       * Arezki Feth <f.a@majerti.fr>;
#       * Miotte Julien <j.m@majerti.fr>;
from pyramid.security import NO_PERMISSION_REQUIRED


CLIENT_ID = "a21dcf08752f7ede0c39d531a5177b5566a54441ff2b9f20b249a8ab043f7c4d"
CLIENT_SECRET = "0a89d8932bd37f684a982fa10723a764b6d5ba0f19a52e2441b4bc3dd6de4af9"
CLIENT_URI = "http://gaston:6543/play"


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
            'redirect_uri': CLIENT_URI,
            'client_id': CLIENT_ID,
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
