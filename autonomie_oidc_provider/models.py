# -*- coding: utf-8 -*-
# * Authors:
#       * TJEBBES Gaston <g.t@majerti.fr>
#       * Arezki Feth <f.a@majerti.fr>;
#       * Miotte Julien <j.m@majerti.fr>;

import time
from datetime import datetime

from sqlalchemy import Column
from sqlalchemy import ForeignKey

from sqlalchemy import Integer
from sqlalchemy import Boolean
from sqlalchemy import DateTime
from sqlalchemy import Unicode

from sqlalchemy.orm import relationship
from sqlalchemy.orm import synonym

from .util import oidc_settings

from .generators import (
    gen_token,
    gen_client_id,
    gen_client_secret,
    crypt_secret,
)

from autonomie.models.base import (
    DBBASE,
    default_table_args,
)


class OidcClient(DBBASE):
    __table_args__ = default_table_args,
    id = Column(Integer, primary_key=True)
    name = Column(Unicode(128), unique=True, nullable=False)
    client_id = Column(Unicode(64), unique=True, nullable=False)
    _client_secret = Column(Unicode(255), unique=True, nullable=False)
    revoked = Column(Boolean, default=False)
    revocation_date = Column(DateTime)
    _salt = None
    redirect_uris = relationship(
        "OidcRedirectUri",
        back_populates='client',
    )
    tokens = relationship("OidcToken", back_populates="client")
    authcodes = relationship("OidcCode", back_populates="client")

    def __init__(self, name, salt=None):
        self.name = name
        self._salt = salt
        self.client_id = gen_client_id()
        self.client_secret = gen_client_secret()

    def new_client_secret(self):
        """
        Create a new client secret and stores its encrypted value in db

        :returns: The secret to be used by the Resource consumer
        :rtype: str
        """
        secret = gen_client_secret()
        self.client_secret = secret
        return secret

    def _get_client_secret(self):
        return self._client_secret

    def _validate_salt(self, salt):
        """
        Check that the given salt could be b64decoded

        :param str salt: The salt to check
        :raises: ValueError
        """
        salt_len = len(salt)
        if salt_len == 0:
            raise ValueError(
                "Missing an oidc.salt setting "
                "(it's length should be a multiple of 4)"
            )
        if salt_len % 4 != 0:
            raise ValueError(
                "oidc.salt configuration length should be a multiple of 4"
            )

    def _set_client_secret(self, client_secret):
        """
        Define the client secret
        1- extract the salt from the current configuration
        2- validates the salt format
        3-
        """
        if self._salt is None:
            self._salt = oidc_settings('salt', '')

        self._validate_salt(self._salt)

        if isinstance(client_secret, unicode):
            client_secret = client_secret.encode('utf-8')
        client_secret = bytes(client_secret)

        self._client_secret = crypt_secret(client_secret, self._salt)

    client_secret = synonym('_client_secret', descriptor=property(
        _get_client_secret, _set_client_secret))

    def revoke(self):
        self.revoked = True
        self.revocation_date = datetime.utcnow()

    def isRevoked(self):
        return self.revoked


class OidcRedirectUri(DBBASE):
    __table_args__ = default_table_args
    id = Column(Integer, primary_key=True)
    uri = Column(Unicode(256), nullable=False)

    client_id = Column(Integer, ForeignKey(OidcClient.id))
    client = relationship(OidcClient)

    def __init__(self, client, uri):
        if OidcRedirectUri.query().filter_by(uri=uri).count() > 0:
            raise Exception("Existing redirectUri")
        self.client = client
        self.uri = uri


class OidcCode(DBBASE):
    __table_args__ = default_table_args
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=False)
    authcode = Column(Unicode(64), unique=True, nullable=False)
    expires_in = Column(Integer, nullable=False, default=10*60)

    revoked = Column(Boolean, default=False)
    revocation_date = Column(DateTime)

    creation_date = Column(DateTime, default=datetime.utcnow)

    client_id = Column(Integer, ForeignKey(OidcClient.id))
    client = relationship(OidcClient)

    def __init__(self, client, user_id):
        self.client = client
        self.user_id = user_id

        self.authcode = gen_token(self.client)

    def revoke(self):
        self.revoked = True
        self.revocation_date = datetime.utcnow()

    def isRevoked(self):
        expiry = time.mktime(self.create_date.timetuple()) + self.expires_in
        if datetime.frometimestamp(expiry) < datetime.utcnow():
            self.revoke()
        return self.revoked


class OidcToken(DBBASE):
    __table_args__ = default_table_args
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=False)
    access_token = Column(Unicode(64), unique=True, nullable=False)
    refresh_token = Column(Unicode(64), unique=True, nullable=False)
    expires_in = Column(Integer, nullable=False, default=60*60)

    revoked = Column(Boolean, default=False)
    revocation_date = Column(DateTime)

    creation_date = Column(DateTime, default=datetime.utcnow)

    client_id = Column(Integer, ForeignKey(OidcClient.id))
    client = relationship(OidcClient)

    def __init__(self, client, user_id):
        self.client = client
        self.user_id = user_id

        self.access_token = gen_token(self.client)
        self.refresh_token = gen_token(self.client)

    def revoke(self):
        self.revoked = True
        self.revocation_date = datetime.utcnow()

    def isRevoked(self):
        expiry = time.mktime(self.creation_date.timetuple()) + self.expires_in
        if datetime.fromtimestamp(expiry) < datetime.utcnow():
            self.revoke()
        return self.revoked

    def refresh(self):
        """
        Generate a new token for this client.
        """

        cls = self.__class__
        self.revoke()
        return cls(self.client, self.user_id)

    def asJSON(self, **kwargs):
        token = {
            'access_token': self.access_token,
            'refresh_token': self.refresh_token,
            'user_id': self.user_id,
            'expires_in': self.expires_in,
        }
        kwargs.update(token)
        return kwargs


def includeme(config):
    """
    void function used to ensure the models are added to the metadatas
    """
    pass
