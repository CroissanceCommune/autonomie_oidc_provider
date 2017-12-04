autonomie_oidc_provider README
=================================

This is still a work in progress.

Open Id connect provider based on Autonomie (http://autonomie.coop).

Only *Authorization Code Flow* is supported

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

redirect_uri : The redirect uri has described in the openid connect specifications (The one passed in the Authorize step)

scopes : The scope the application is requesting (at least the openid scope should be provided) e.g: "openid profile"

cert_salt : A salt random key that will be used to encrypt the client secret in the database

After generating both client_id and client_secret. The client app is able to request authentication.


Authorize Endpoint
........................

The client app can call the Authorization url :

https://myoidc_provider.com/oidc/authorize

It allows :

    - Authenticate a user
    - Get an Authorization code in the response

Token url
.........................

Called in the background, the Token endpoint is accessible at the following url :

https://myoidc_provider.com/oidc/token

The RFC : https://tools.ietf.org/html/rfc6749#section-2.3.1

Describes Client Password transmission methods.

Supported client auth method :

* Through request headers : Basic auth tokens are supported
* Through request POST params : client_id and client_secret keys are then expected

In the response you get :

    - An access token with mandatory informations
    - An id_token JWS encrypted as described in the spec
    - Since we use code flow, the id_token also returns the at_hash access_token identification key


Autonomie integration
-----------------------

In your Autonomie's ini file add the following :

.. codeblock:: python

    pyramid.includes =
                        ...
                        autonomie_oidc_provider
                        ...


(That's for model registration so that the db startup initialize the tables)

And add the following :

.. codeblock::

    autonomie.includes =
                        ...
                        autonomie_oidc_provider.plugin
                        ...

That register OIDC client application configuration UI :

* routes
* views
* traversal tree branch
* template api stuff
* templates
* menu entries
