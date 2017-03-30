# -*- coding: utf-8 -*-
from pyramid.interfaces import IBeforeRender
from pyramid.events import subscriber

from autonomie_oidc_provider.template_api import TemplateApi

def add_api_subscriber(event):
    """
    Add an api object to the template context for rendering purpose
    """
    if event.get('renderer_name', '') != 'json':
        request = event['request']
        context = event['context']
        event['api'] = TemplateApi(context, request)


def includeme(config):
    config.add_subscriber(add_api_subscriber, IBeforeRender)
