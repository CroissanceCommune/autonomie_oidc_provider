autonomie_oidc_provider README
=================================

This is still a work in progress.

Open Id connect provider based on Autonomie (http://autonomie.coop).

Getting Started
---------------

- cd <directory containing this file>

- $VENV/bin/pip install -e .

- $VENV/bin/initialize_autonomie_oidc_provider_db development.ini

- $VENV/bin/pserve development.ini


Authorization handling
-----------------------

Generate a new client's key :

.. code-block:: console

    oidc-manage <config_uri> clientadd --client=<client> --uri=<redirect_uri> --scopes=<scopes> --cert_salt=<cert_salt>

config_uri : Your ini file

client: A label for your client

redirect_uri : The redirect uri has described in the openid connect specifications

scopes : The scope the application is requesting (at least the openid scope should be provided)

cert_salt : A salt random key that will be used to encrypt the client secret in the database

After generating both client_id and client_secret. The client app is able to request authentication.


Authorize Url
..............

https://myoidc_provider.com/oidc/authorize

Token url
...........

https://myoidc_provider.com/oidc/token
