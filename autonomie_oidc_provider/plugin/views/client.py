# -*- coding: utf-8 -*-
# * Authors:
#       * TJEBBES Gaston <g.t@majerti.fr>
#       * Arezki Feth <f.a@majerti.fr>;
#       * Miotte Julien <j.m@majerti.fr>;
"""
OidcClient configuration views

Those views are only presneted inside Autonomie
"""
import logging
import colander

from deform_extensions import GridFormWidget
from pyramid.httpexceptions import HTTPFound
from sqlalchemy import or_
from sqlalchemy.orm import load_only

from autonomie_base.mail import send_mail
from autonomie.utils.widgets import ViewLink
from autonomie.views import (
    BaseFormView,
    BaseEditView,
    BaseListView,
    cancel_btn,
    submit_btn,
)
from autonomie_oidc_provider.models import (
    OidcClient,
)
from autonomie_oidc_provider.plugin.views.forms import (
    get_client_schema,
    get_client_list_schema,
)

logger = logging.getLogger('autonomie.oidc.plugin.views')


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
        client = self.schema.objectify(appstruct)
        refresh_client_secret(self.request, client)
        self.dbsession.add(client)
        self.dbsession.flush()
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
    request.actionmenu.add(
        ViewLink(
            u"Revenir à la liste",
            path="/oidc_config/clients",
        )
    )
    return dict(
        title=u"Application : {0}".format(context.name)
    )


class ClientEditView(BaseEditView):
    schema = get_client_schema()
    redirect_route = "/oidc_config/clients"

    def before(self, form):
        BaseEditView.before(self, form)
        self.request.actionmenu.add(
            ViewLink(
                u"Revenir à la liste",
                path="/oidc_config/clients",
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

    refresh_client_secret(request, context, newone=False)

    return HTTPFound(request.current_route_path(_query={}))


class ClientListView(BaseListView):
    """
    Client listing view
    """
    add_template_vars = ('title', 'stream_actions',)
    title = u"Liste des clients ayant le droit d'accéder aux informations "
    u"Autonomie"
    schema = get_client_list_schema()
    default_sort = "name"
    default_direction = "asc"
    sort_columns = {'name': OidcClient.name}

    def query(self):
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
        if not oidc_client.revoked:
            yield (
                self.request.route_path(
                    "/oidc_config/clients/{id}",
                    id=oidc_client.id,
                    _query={'action': 'revoke'}
                ),
                u"Révoquer",
                u"Révoquer les droits de cette application",
                u"fa fa-archive",
                {"onclick": u"return window.confirm('Cette application ne"
                 u"pourra plus accéder à Autonomie. Continuer ?');"}
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
        renderer="autonomie_oidc_provider:templates/plugin/client.mako",
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
        renderer="autonomie_oidc_provider:templates/plugin/clients.mako",
    )


def includeme(config):
    add_routes(config)
    add_views(config)
