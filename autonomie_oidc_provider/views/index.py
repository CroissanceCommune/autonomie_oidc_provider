# -*- coding: utf-8 -*-
# * Authors:
#       * TJEBBES Gaston <g.t@majerti.fr>
#       * Arezki Feth <f.a@majerti.fr>;
#       * Miotte Julien <j.m@majerti.fr>;
from pyramid.security import NO_PERMISSION_REQUIRED
from pyramid.httpexceptions import HTTPBadRequest


def index_view(request):
    """
    Simple index view

    :param obj request: The Pyramid request
    """
    raise HTTPBadRequest(
        "Missing mandatory parameters, "
        "see : http://openid.net/specs/openid-connect-core-1_0.html")


def includeme(config):
    """
    Add the index view
    """
    config.add_view(
        index_view,
        route_name="/",
        permission=NO_PERMISSION_REQUIRED,
    )
