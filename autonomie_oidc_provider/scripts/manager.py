# -*- coding: utf-8 -*-
# * Authors:
#       * TJEBBES Gaston <g.t@majerti.fr>
#       * Arezki Feth <f.a@majerti.fr>;
#       * Miotte Julien <j.m@majerti.fr>;
from autonomie.scripts.utils import (
    command,
    get_value,
)


def add_client_command(args, env):
    """
    Add a client in the database

    :param dict args: The arguments passed by command line
    :param dict env: an environment dict (pyramid_env returned after bootstrap)
    """
    from autonomie_base.models.base import DBSESSION
    from autonomie_oidc_provider.models import (
        OidcClient,
        OidcRedirectUri,
    )
    redirect_uri = get_value(args, 'uri')
    client_name = get_value(args, 'client')
    client_scopes = get_value(args, 'scopes')
    cert_salt = get_value(args, 'cert_salt', '')

    if 'openid' not in client_scopes:
        client_scopes = 'openid ' + client_scopes

    if redirect_uri is None or client_name is None:
        raise KeyError("Missing mandatory argument")

    assert OidcClient.query().filter_by(name=client_name).first() is None, \
        "This client is already registered"

    assert OidcRedirectUri.query().filter_by(
        uri=redirect_uri
    ).first() is None,  \
        "This redirect_uri is already registered"

    db = DBSESSION()

    client = OidcClient(
        name=client_name,
        scopes=client_scopes,
        cert_salt=cert_salt,
    )
    secret = client.new_client_secret()
    db.add(client)
    db.flush()
    redirecturi = OidcRedirectUri(client=client, uri=redirect_uri)
    db.add(redirecturi)
    print(
        """New client {client.name} created :

            OpenId connect tokens :
            client id : {client.client_id}
            client secret : {secret}

            WARNING : Those informations should be kept confidential since they
            are identification tokens
        """.format(client=client, secret=secret)
    )


def revoke_client_command(args, env):
    """
    Revoke a client secret

    :param dict args: The arguments passed by command line
    :param dict env: an environment dict (pyramid_env returned after bootstrap)
    """
    from autonomie_base.models.base import DBSESSION
    from autonomie_oidc_provider.models import (
        OidcClient,
    )
    client_id = get_value(args, 'client_id')

    if client_id is None:
        raise KeyError("Missing mandatory argument")

    db = DBSESSION()

    client = OidcClient.query().filter_by(client_id=client_id).first()
    if client is None:
        raise KeyError("Unknown client")

    client.revoke()
    db.merge(client)
    db.flush()

    print(
        """The client {client.name} with id {client.client_id} has been revoked
        """.format(client=client)
    )


def refresh_secret_command(args, env):
    """
    Refresh the authentication informations related to the given client

    :param dict args: The arguments passed by command line
    :param dict env: an environment dict (pyramid_env returned after bootstrap)
    """
    from autonomie_base.models.base import DBSESSION
    from autonomie_oidc_provider.models import (
        OidcClient,
    )
    client_id = get_value(args, 'client_id')

    if client_id is None:
        raise KeyError("Missing mandatory argument")

    db = DBSESSION()

    client = OidcClient.query().filter_by(client_id=client_id).first()
    if client is None:
        raise KeyError("Unknown client")

    secret = client.new_client_secret()
    client.revoked = False
    db.merge(client)
    db.flush()

    print(
        """New secret token generated for "{client.name}" :

        OpenId connect tokens :
          client id : {client.client_id}
          client secret : {secret}

          WARNING : Those informations should be kept confidential since they
          are identification tokens
        """.format(client=client, secret=secret)
    )


def manage():
    """Autonomie OpenId Connect Provider Management

    Usage:
        oidc-manage <config_uri> clientadd --client=<client> --uri=<redirect_uri> --scopes=<scopes> --cert_salt=<cert_salt>
        oidc-manage <config_uri> clientrevoke --client_id=<client_id>
        oidc-manage <config_uri> clientrefresh --client_id=<client_id>

    o clientadd : get a client secret for this new client
    o clientrevoke : revoke the given client

    Options:

        -h --help     Show this screen.
    """
    def callback(arguments, env):
        if arguments['clientadd']:
            func = add_client_command
        elif arguments['clientrevoke']:
            func = revoke_client_command
        elif arguments['clientrefresh']:
            func = refresh_secret_command
        return func(arguments, env)

    try:
        return command(callback, manage.__doc__)
    finally:
        pass
