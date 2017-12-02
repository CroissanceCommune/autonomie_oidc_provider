# -*- coding: utf-8 -*-
# * Authors:
#       * TJEBBES Gaston <g.t@majerti.fr>
#       * Arezki Feth <f.a@majerti.fr>;
#       * Miotte Julien <j.m@majerti.fr>;
"""
Insert custom traversal security stuff inside the main application traversal
tree
"""
from pyramid.interfaces import IRootFactory
from autonomie.utils.security import (
    TraversalDbAccess,
    TraversalNode,
    get_base_acl,
)
from autonomie_oidc_provider import models


class OidcNode(TraversalNode):
    """
    Base Traversal node used to access oidc related entities
    """
    def __init__(self):
        self['clients'] = TraversalDbAccess(
            self,
            'clients',
            'client',
            models.OidcClient,
        )


def includeme(config):
    root = config.registry.getUtility(IRootFactory)
    root.register_subtree('oidc', OidcNode())

    models.OidcClient.__acl__ = property(get_base_acl)
