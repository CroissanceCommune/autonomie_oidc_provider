# -*- coding: utf-8 -*-
# * Authors:
#       * TJEBBES Gaston <g.t@majerti.fr>
#       * Arezki Feth <f.a@majerti.fr>;
#       * Miotte Julien <j.m@majerti.fr>;
"""
OidcClient configuration views

Those views are only presneted inside Autonomie
"""
import colander
import deform

from deform_extensions import GridFormWidget

from colanderalchemy import SQLAlchemySchemaNode
from pyramid.httpexceptions import HTTPFound
from sqlalchemy.orm import load_only

from autonomie.forms.lists import BaseListsSchema
from autonomie.forms import mail_validator
from autonomie.forms.widgets import CleanMappingWidget
from autonomie.utils.widgets import ViewLink
from autonomie.views import (
    BaseFormView,
    BaseListView,
    cancel_btn,
    submit_btn,
)

from autonomie_oidc_provider.models import (
    OidcClient,
    OidcRedirectUri,
)

SCOPES = (
    ('openid', u"Authentification seule"),
    ('profile', u"Données de profil (nom, prénom, email, groupes...)"),
)


def get_client_schema():
    """
    Return the colander Schema for OidcClient add/edit
    """
    schema = SQLAlchemySchemaNode(
        OidcClient,
        includes=(
            'id', 'name', 'admin_email', 'scopes', 'logout_uri', 'redirect_uris'
        )
    )
    schema['admin_email'].widget = deform.widget.TextInputWidget(
        input_prepend='@'
    )
    schema['admin_email'].validator = mail_validator()

    schema['scopes'].typ = colander.Set()
    schema['scopes'].widget = deform.widget.CheckboxChoiceWidget(
        values=SCOPES,
    )

    schema['redirect_uris'].children[0].widget = CleanMappingWidget()
    return schema


FORM_LAYOUT = (
    (
        ('name', 6),
        ('admin_email', 6),
    ),
    (
        ('scopes', 12),
    ),
    (
        ('redirect_uris', 12),
    ),
    (
        ('logout_uri', 12),
    ),
)


class ClientAddView(BaseFormView):
    """
    View used to add an open id connect client
    """
    schema = get_client_schema()
    title = u"Ajouter une application cliente Open ID Connect"
    buttons = (submit_btn, cancel_btn)

    def before(self, form):
        self.request.actionmenu.add(
            ViewLink(
                u"Revenir à la liste",
                path="/oidc_config/clients",
            )
        )
        form.widget = GridFormWidget(named_grid=FORM_LAYOUT)
        form.set_appstruct(
            {'scopes': ('openid', 'profile')}
        )

    def submit_success(self, appstruct):
        """
        launched on successfull submission

        :param dict appstruct: The validated form datas
        """
        client = OidcClient(
            name=appstruct['name'],
            scopes=' '.join(appstruct['scopes'])
        )
        client.admin_email = appstruct.get('admin_email', '')
        client.logout_uri = appstruct.get('logout_uri', '')

        secret = client.new_client_secret()
        self.request.session.flash(
            u"L'application {0} a été créée, les identifiants à transmettre à "
            u"l'administrateur <ul><li>Client ID : {1}</li><li>"
            u"Client secret : {2}</li></ul>".format(
                client.name,
                client.client_id,
                secret
            )
        )
        self.dbsession.add(client)
        self.dbsession.flush()
        redirect_uri = OidcRedirectUri(client, appstruct['redirect_uri'])
        self.dbsession.add(redirect_uri)
        return HTTPFound(
            self.request.route_path(
                "/oidc_config/clients",
            )
        )

    def cancel_success(self, *args, **kwargs):
        return HTTPFound(
            self.request.route_path(
                "/oidc_config/clients",
            )
        )

    cancel_failure = cancel_success


def client_view(context, request):
    """
    Collect datas for the client display view
    """
    return dict(
        title=u"Application : {0}".format(context.name)
    )


class ClientEditView(BaseFormView):
    schema = get_client_schema()

    def before(self, form):
        form.set_appstruct(
            {
                'scopes': self.context.get_scopes(),
                'redirect_uri': self.context.redirect_uris[0].uri,
                'name': self.context.name,
            }
        )

    def submit_success(self, appstruct):
        """
        launched on successfull submission

        :param dict appstruct: The validated form datas
        """
        if 'scopes' in appstruct:
            self.context.scopes = ' '.join(appstruct.get('scopes'))

        if 'name' in appstruct:
            self.context.name = appstruct.get('name')

        if 'redirect_uri' in appstruct:
            self.context.redirect_uris[0].uri = appstruct['redirect_uri']

        self.dbsession.merge(self.context)
        self.dbsession.merge(self.context.redirect_uris[0])
        return HTTPFound(
            self.request.route_path(
                "/oidc_config/clients",
            )
        )


def client_revoke_view(context, request):
    """
    View used to revoke a client

    :param obj context: The OidcClient object
    """
    context.revoke()
    request.dbsession.merge(context)
    request.session.flash(
        u"Les droits de l'application {0} ont bien été supprimés.".format(
            context.name
        )
    )
    return HTTPFound(request.route_path("/oidc_config/clients"))


def client_secret_refresh_view(context, request):
    """
    View used to refresh a client_secret

    :param obj context: The OidcClient object
    """
    if context.revoked:
        context.revoked = False
        context.revocation_date = None

    new_client_secret = context.new_client_secret()
    request.dbsession.merge(context)
    request.session.flash(
        u"Les identifiants de l'application {0} sont désormais : "
        u"<ul><li>Client ID : {1}</li><li>Client Secret {2}</li></ul>.".format(
            context.name, context.client_id, new_client_secret
        )
    )
    return HTTPFound(request.current_route_path(_query={}))


class ClientListView(BaseListView):
    """
    Client listing view
    """
    add_template_vars = ('title', 'stream_actions',)
    title = u"Liste des clients ayant le droit d'accéder aux informations "
    u"Autonomie"
    schema = BaseListsSchema()
    default_sort = "name"
    default_direction = "asc"
    sort_columns = {'name': OidcClient.name}

    def query(self):
        return OidcClient.query().options(
            load_only('name', 'client_id', 'scopes'),
        )

    def filter_search(self, query, appstruct):
        search = appstruct.get('search')
        if search not in (None, colander.null, ''):
            query = query.filter(
                OidcClient.name.like(u'%s{0}%s'.format(search))
            )
        return query

    def stream_actions(self, oidc_client):
        """
        Stream actions available for the given oidc_client

        :param obj oidc_client: An OidcClient instance
        """
        yield (
            self.request.route_path(
                "/oidc_config/clients/{id}",
                id=oidc_client.id,
            ),
            u"Voir",
            u"Voir cet élément",
            u"fa fa-eye",
            {}
        )
        yield (
            self.request.route_path(
                "/oidc_config/clients/{id}",
                id=oidc_client.id,
                _query={'action': 'edit'}
            ),
            u"Modifier",
            u"Modifier cet élément",
            u"pencil",
            {}
        )
        yield (
            self.request.route_path(
                "/oidc_config/clients/{id}",
                id=oidc_client.id,
                _query={'action': 'revoke'}
            ),
            u"Révoquer",
            u"Révoquer les droits de cette application",
            u"fa fa-archive",
            {"onclick": u"return window.confirm('Cette application ne pourra "
             u"plus accéder à Autonomie. Continuer ?');"}
        )


def add_routes(config):
    config.add_route(
        "/oidc_config/clients",
        "/oidc_config/clients"
    )
    config.add_route(
        "/oidc_config/clients/{id}",
        "/oidc_config/clients/{id}",
        traverse="/oidc/clients/{id}",
    )


def add_views(config):
    config.add_view(
        ClientAddView,
        route_name="/oidc_config/clients",
        request_param="action=add",
        permission="admin.oidc",
        renderer="autonomie:templates/base/formpage.mako",
    )
    config.add_view(
        ClientEditView,
        route_name="/oidc_config/clients/{id}",
        request_param="action=edit",
        permission="admin.oidc",
        renderer="autonomie:templates/base/formpage.mako",
    )
    config.add_view(
        client_view,
        route_name="/oidc_config/clients/{id}",
        permission="admin.oidc",
        renderer="autonomie_oidc_provider:templates/config_ui/client.mako",
    )
    config.add_view(
        client_revoke_view,
        route_name="/oidc_config/clients/{id}",
        request_param="action=revoke",
        permission="admin.oidc",
    )
    config.add_view(
        client_secret_refresh_view,
        route_name="/oidc_config/clients/{id}",
        request_param="action=refresh_secret",
        permission="admin.oidc",
    )
    config.add_view(
        ClientListView,
        route_name="/oidc_config/clients",
        permission="admin.oidc",
        renderer="autonomie_oidc_provider:templates/config_ui/clients.mako",
    )


def includeme(config):
    add_routes(config)
    add_views(config)
