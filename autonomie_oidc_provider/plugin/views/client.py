# -*- coding: utf-8 -*-
# * Authors:
#       * TJEBBES Gaston <g.t@majerti.fr>
#       * Arezki Feth <f.a@majerti.fr>;
#       * Miotte Julien <j.m@majerti.fr>;
"""
OidcClient configuration views

Those views are only presneted inside Autonomie
"""
import os
import logging
import colander

from deform_extensions import GridFormWidget
from pyramid.httpexceptions import HTTPFound
from sqlalchemy import or_
from sqlalchemy.orm import load_only

from autonomie_base.mail import send_mail
from autonomie.views.admin.tools import (
    AdminTreeMixin,
    AdminCrudListView,
    BaseAdminEditView,
    BaseAdminAddView
)
from autonomie.views import (
    BaseView,
    cancel_btn,
    submit_btn,
)
from autonomie.views.admin import AdminIndexView
from autonomie_oidc_provider.models import (
    OidcClient,
)
from autonomie_oidc_provider.plugin.views.forms import (
    get_client_schema,
)
from autonomie.utils.widgets import Link

logger = logging.getLogger('autonomie.oidc.plugin.views')


OIDC_INDEX_URL = "/admin/oidc"
OIDC_CLIENT_URL = os.path.join(OIDC_INDEX_URL, "clients")
OIDC_CLIENT_ITEM_URL = os.path.join(OIDC_CLIENT_URL, "{id}")


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


NEW_APP_MAIL_SUBJECT_TMPL = u"Autonomie Open ID connect : Identifiants pour \
l'application {client.name}"

REFRESH_APP_MAIL_SUBJECT_TMPL = u"Autonomie Open ID connect : Nouveaux \
identifiants pour l'application {client.name}"


NEW_APP_MAIL_BODY_TMPL = u"""
Les idenfitiants ci-dessous ont été créés pour permettre à l'application
{client.name} d'accéder au service d'authentification OpenId Connect
d'Autonomie.

Ces identifiants sont confidentiels et ne doivent être utilisés que pour
permettre aux utilisateurs de se connecter à l'application {client.name}.  Il
est préférable de supprimer ce message après avoir configuré votre application.

Les identifiants :
Client ID : {client.client_id}
Client secret : {client_secret}

Le présent message, ainsi que tout fichier qui y est joint, est envoyé à
l'intention exclusive de son ou de ses destinataires; il est de nature
confidentielle et peut constituer une information privilégiée. Nous avertissons
toute personne autre que le destinataire prévu que tout examen, réacheminement,
impression, copie, distribution ou toute autre utilisation de ce message et
tout document joint est strictement interdit. Si vous n'êtes pas le
destinataire prévu, veuillez en aviser immédiatement l'expéditeur par retour de
courriel et supprimer ce message et tout document joint de votre système.
Merci!
"""


REFRESH_APP_MAIL_BODY_TMPL = u"""
Les idenfitiants de l'application {client.name} permettant d'accéder au
service d'authentification OpenId Connect d'Autonomie ont été renouvellés.
Les idenfitiants précédemment utilisés ne sont plus valides.

Ces identifiants sont confidentiels et ne doivent être utilisés que pour
permettre aux utilisateurs de se connecter à l'application {client.name}.  Il
est préférable de supprimer ce message après avoir configuré votre application.

Les identifiants :
Client ID : {client.client_id}
Client secret : {client_secret}

Le présent message, ainsi que tout fichier qui y est joint, est envoyé à
l'intention exclusive de son ou de ses destinataires; il est de nature
confidentielle et peut constituer une information privilégiée. Nous avertissons
toute personne autre que le destinataire prévu que tout examen, réacheminement,
impression, copie, distribution ou toute autre utilisation de ce message et
tout document joint est strictement interdit. Si vous n'êtes pas le
destinataire prévu, veuillez en aviser immédiatement l'expéditeur par retour de
courriel et supprimer ce message et tout document joint de votre système.
Merci!
"""


NEW_APP_FLASH_TMPL = u"""
L'application {client.name} a été créée, les identifiants à transmettre à
 l'administrateur
    <ul>
    <li>Client ID : {client.client_id}</li>
    <li>Client secret : {client_secret}</li>
    </ul>
"""

REFRESH_APP_FLASH_TMPL = u"""
De nouveaux identifiants ont été générés pour l'application {client.name}.
Voici les identifiants à transmettre àl'administrateur
    <ul>
    <li>Client ID : {client.client_id}</li>
    <li>Client secret : {client_secret}</li>
    </ul>
"""


def send_tokens_by_email(request, client_secret, client, newone):
    """
    Send the new client authorization tokens to the given client

    :param str client_secret: The unecrypted client secret
    :param obj client: The OidcClient
    :param bool newone: Does this call concerns newly created applications
    """
    logger.debug(u"We should send an email to {0}".format(client.admin_email))

    if newone:
        subj_tmpl = NEW_APP_MAIL_SUBJECT_TMPL
        body_tmpl = NEW_APP_MAIL_BODY_TMPL
    else:
        subj_tmpl = REFRESH_APP_MAIL_SUBJECT_TMPL
        body_tmpl = REFRESH_APP_MAIL_BODY_TMPL

    message_subject = subj_tmpl.format(client=client)
    message_body = body_tmpl.format(
        client=client,
        client_secret=client_secret
    )
    result = send_mail(
        request,
        [client.admin_email],
        message_body,
        message_subject
    )
    if not result:
        raise Exception(u"An error occured during mail sending")


def flash_client_secret_to_ui(request, secret, client, newone=True):
    """
    Flash the client app secret's informations to the end user

    :param obj request: The pyramid request object
    :param str secret: The client secret
    :param obj client: The OidcClient object
    :param bool newone: Does this call concerns newly created applications
    """
    if newone:
        flash_msg_tmpl = NEW_APP_FLASH_TMPL
    else:
        flash_msg_tmpl = REFRESH_APP_FLASH_TMPL
    request.session.flash(
        flash_msg_tmpl.format(
            client=client,
            client_secret=secret
        )
    )


def refresh_client_secret(request, client, newone=True):
    """
    Renew the client secret and send it to the admin

    :param obj request: The pyramid request object
    :param obj client: The OidcClient object
    :param bool newone: Does this call concerns newly created applications
    """
    secret = client.new_client_secret()
    if client.admin_email:
        try:
            send_tokens_by_email(request, secret, client, newone)
            request.session.flash(
                u"Les identifiants de connexion ont été envoyés à l'adresse : "
                u"{0}".format(client.admin_email)
            )
        except:
            logger.exception(u"Erreur à l'envoi de mail")
            request.session.flash(
                u"Erreur d'envoi d'email à l'adresse {0}".format(
                    client.admin_email
                ),
                'error'
            )
            flash_client_secret_to_ui(request, secret, client, newone)
    else:
        flash_client_secret_to_ui(request, secret, client, newone)


class ClientAddView(BaseAdminAddView):
    """
    View used to add an open id connect client
    """
    route_name = OIDC_CLIENT_URL
    title = u"Ajouter une application cliente Open ID Connect"
    schema = get_client_schema()
    buttons = (submit_btn, cancel_btn)
    factory = OidcClient

    def before(self, form):
        form.widget = GridFormWidget(named_grid=FORM_LAYOUT)
        form.set_appstruct(
            {'scopes': ('openid', 'profile')}
        )

    def on_add(self, client, appstruct):
        """
        launched on successfull submission

        :param dict appstruct: The validated form datas
        """
        refresh_client_secret(self.request, client)
        self.dbsession.merge(client)
        return client

    def cancel_success(self, *args, **kwargs):
        return self.redirect()

    cancel_failure = cancel_success


class ClientView(BaseView, AdminTreeMixin):
    """
    Collect datas for the client display view
    """
    route_name = OIDC_CLIENT_ITEM_URL

    @property
    def title(self):
        return u"Application : {0}".format(self.context.name)

    def __call__(self):
        return dict(
            breadcrumb=self.breadcrumb,
            back_link=self.back_link,
            title=self.title
        )


class ClientEditView(BaseAdminEditView):
    route_name = OIDC_CLIENT_ITEM_URL
    title = u"Modifier ce du client"
    schema = get_client_schema()
    factory = OidcClient


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
    return HTTPFound(request.route_path(OIDC_CLIENT_URL))


def client_secret_refresh_view(context, request):
    """
    View used to refresh a client_secret

    :param obj context: The OidcClient object
    """
    if context.revoked:
        context.revoked = False
        context.revocation_date = None

    refresh_client_secret(request, context, newone=False)

    return HTTPFound(request.current_route_path(_query={}))


class ClientListView(AdminCrudListView):
    """
    Client listing view
    """
    route_name = OIDC_CLIENT_URL
    item_route_name = OIDC_CLIENT_ITEM_URL

    title = u"Module d'authentification centralisée (SSO)"
    description = (
        u"Configurer les droits d'accès des applications "
        u"utilisant les données Autonomie et son service "
        u"d'authentification Open Id connect"
    )
    columns = [
        'Application', 'Client ID', u"Autorisation (scope)",
        u"Urls de redirection"
    ]

    def stream_columns(self, item):
        if item.revoked:
            label = u"""
            <span class='label label-danger'>
                Cette application a été révoquée
            </span>&nbsp;{}""".format(item.name)
        else:
            label = item.name
        yield label

        yield item.client_id

        scopes = u""
        for scope in item.get_scopes():
            scopes += u"<li>{}</li>".format(scope)
        yield u"""<ul>{}</ul>""".format(scopes)

        redirections = u""
        for redir in item.redirect_uris:
            redirections += u"<li>{}</li>".format(redir.uri)
        yield u"""<ul>{}</ul>""".format(redirections)

    def load_items(self):
        return OidcClient.query().options(
            load_only('name', 'client_id', 'scopes'),
        )

    def filter_search(self, query, appstruct):
        search = appstruct.get('search')
        logger.debug(u"Searching : %s" % search)
        if search not in (None, colander.null, ''):
            query = query.filter(
                or_(
                    OidcClient.name.like(u'%{0}%'.format(search)),
                    OidcClient.client_id.like(u'%{0}%'.format(search))
                )
            )
        return query

    def stream_actions(self, oidc_client):
        """
        Stream actions available for the given oidc_client

        :param obj oidc_client: An OidcClient instance
        """
        yield Link(
            self._get_item_url(oidc_client),
            u"Voir",
            icon=u"eye",
        )
        yield Link(
            self._get_item_url(oidc_client, action="edit"),
            u"Modifier",
            icon=u"pencil",
        )
        if not oidc_client.revoked:
            yield Link(
                self._get_item_url(oidc_client, action="revoke"),
                u"Révoquer",
                title=u"Révoquer les droits de cette application",
                icon=u"archive",
                confirm=u"Cette application ne"
                u"pourra plus accéder à Autonomie. Continuer ?"
            )


def add_routes(config):
    config.add_route(OIDC_INDEX_URL, OIDC_INDEX_URL)
    config.add_route(OIDC_CLIENT_URL, OIDC_CLIENT_URL)
    config.add_route(
        OIDC_CLIENT_ITEM_URL,
        OIDC_CLIENT_ITEM_URL,
        traverse="/oidc/clients/{id}",
    )


def add_views(config):
    config.add_admin_view(
        ClientListView,
        parent=AdminIndexView,
        permission="admin.oidc",
        renderer="autonomie:templates/admin/crud_list.mako",
    )
    config.add_admin_view(
        ClientAddView,
        parent=ClientListView,
        request_param="action=add",
        permission="admin.oidc",
        renderer='admin/crud_add_edit.mako',
    )
    config.add_admin_view(
        ClientEditView,
        parent=ClientListView,
        request_param="action=edit",
        permission="admin.oidc",
    )
    config.add_admin_view(
        ClientView,
        parent=ClientListView,
        permission="admin.oidc",
        renderer="autonomie_oidc_provider:templates/plugin/client.mako",
    )
    config.add_view(
        client_revoke_view,
        route_name=OIDC_CLIENT_ITEM_URL,
        request_param="action=revoke",
        permission="admin.oidc",
        layout="default",
    )
    config.add_view(
        client_secret_refresh_view,
        route_name=OIDC_CLIENT_ITEM_URL,
        request_param="action=refresh_secret",
        permission="admin.oidc",
        layout="default",
    )


def includeme(config):
    add_routes(config)
    add_views(config)
