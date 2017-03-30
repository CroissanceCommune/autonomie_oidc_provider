# -*- coding: utf-8 -*-
from js.deform import deform_css
from js.bootstrap import bootstrap
from autonomie_oidc_provider import fanstatic


class FormLayout(object):
    def __init__(self, context, request):
        self.context = context
        self.request = request
        deform_css.need()
        bootstrap.need()
        fanstatic.main_css.need()


def includeme(config):
    """
    Include the layout in the current configuration

    :param obj config: A Configurator object
    """
    config.add_layout(
        FormLayout,
        "autonomie_oidc_provider:templates/form_layout.pt",
        name='formlayout'
    )
