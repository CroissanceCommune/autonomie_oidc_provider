# -*- coding: utf-8 -*-
# * Authors:
#       * TJEBBES Gaston <g.t@majerti.fr>
#       * Arezki Feth <f.a@majerti.fr>;
#       * Miotte Julien <j.m@majerti.fr>;
from zope.interface import implementer
from pyramid_oauth2_provider.interfaces import IAuthCheck


@implementer(IAuthCheck)
class Test:
    def checkauth(self, username, password):
        return True
