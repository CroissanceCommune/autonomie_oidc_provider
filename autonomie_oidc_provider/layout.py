# -*- coding: utf-8 -*-
from autonomie.default_layouts import DefaultLayout


def includeme(config):
    """
    Include the layout in the current configuration

    :param obj config: A Configurator object
    """
    config.add_layout(
        DefaultLayout,
        "autonomie:templates/layouts/login.mako"
    )
    config.add_layout(
        DefaultLayout,
        "autonomie:templates/layouts/login.mako",
        name='login'
    )
