# -*- coding: utf-8 -*-
# * Authors:
#       * TJEBBES Gaston <g.t@majerti.fr>
#       * Arezki Feth <f.a@majerti.fr>;
#       * Miotte Julien <j.m@majerti.fr>;
import datetime
import deform

from jwkest.jws import (
    JWS,
    left_hash,
)
from jwkest.jwk import SYMKey

from sqlalchemy import Column
from sqlalchemy import ForeignKey

from sqlalchemy import Integer
from sqlalchemy import Boolean
from sqlalchemy import DateTime
from sqlalchemy import Unicode

from sqlalchemy.orm import relationship
from sqlalchemy.orm import synonym

from .util import (
    dt_to_timestamp,
)

from .generators import (
    gen_token,
    gen_client_id,
    gen_client_secret,
    crypt_secret,
    gen_salt,
)

from autonomie_base.models.base import (
    DBBASE,
    default_table_args,
    DBSESSION,
)


MAC = 'HS256'


def get_client_by_client_id(client_id, valid=True):
    """
    Return The client matching the given client_id

    :param str client_id: The client_id to look for
    :param bool valid: Only non-revoked clients ?
    :returns: A OidcClient instance (default None)
    :rtype: obj
    """
    query = OidcClient.query().filter_by(client_id=client_id)
    if valid:
        query = query.filter_by(revoked=False)
    return query.first()


def get_code_by_client_id(client_id, code):
    """
    Find a code issued by this Provider

    :param str client_id: The client_id to look for
    :param str code: The code to check
    :returns: The OidcCode instance
    :rtype: obj
    """
    query = OidcCode.query().filter_by(client_id=client_id)
    query = query.filter_by(authcode=code)
    return query.first()


class OidcClient(DBBASE):
    __table_args__ = default_table_args,
    id = Column(
        Integer,
        primary_key=True,
        info={'colanderalchemy': {'widget': deform.widget.HiddenWidget()}},
    )
    name = Column(
        Unicode(128),
        unique=True,
        nullable=False,
        info={
            'colanderalchemy': {
                'title': u"Nom de l'application"
            }
        }
    )
    client_id = Column(
        Unicode(64),
        unique=True,
        nullable=False,
        info={'colanderalchemy': {'exclude': True}}
    )
    _client_secret = Column(
        Unicode(255),
        unique=True,
        nullable=False,
        info={'colanderalchemy': {'exclude': True}}
    )
    revoked = Column(
        Boolean,
        default=False,
        info={'colanderalchemy': {'exclude': True}}
    )
    revocation_date = Column(
        DateTime,
        info={'colanderalchemy': {'exclude': True}}
    )
    scopes = Column(
        Unicode(255),
        nullable=False,
        info={
            'colanderalchemy': {
                'title': u"Données mise à disposition de l'application",
                'description': u"Au-delà de l'authentification, l'application "
                u"peut demander à accéder à d'autres informations, cela doit "
                u"être autorisée ici",
            }
        }
    )

    salt = Column(
        Unicode(255),
        nullable=False,
        info={'colanderalchemy': {'exclude': True}}
    )
    cert_salt = Column(
        Unicode(255),
        default='',
        info={'colanderalchemy': {'exclude': True}}
    )
    admin_email = Column(
        Unicode(255),
        default='',
        info={
            'colanderalchemy': {
                'title': u"Adresse email de l'administrateur",
                'description': u"Les informations de connexion de l'application"
                u" seront transmises directement à cette adresse",
            }
        }
    )
    logout_uri = Column(
        Unicode(255),
        default='',
        info={
            'colanderalchemy': {
                'title': u"Url de déconnexion",
                'description': u"Lorsqu'un utilisateur se déconnecte auprès du"
                u" service d'authentification centralisée, cette adresse sera "
                u"appelée pour assurer que les utilisateurs soient déconnectés "
                u"de l'application seront transmises directement à cette "
                u"adresse",
            }
        }
    )

    redirect_uris = relationship(
        "OidcRedirectUri",
        cascade="all, delete-orphan",
        back_populates='client',
        info={
            'colanderalchemy': {
                'title': u"Urls de redirection",
                "description": u"Urls de redirection OpenId Connect utilisée "
                u"pour renvoyer l'utilisateur vers l'application après "
                u"authentification",
                "widget": deform.widget.SequenceWidget(
                    add_subitem_text_template=u"Ajouter une url de redirection"
                ),
            }
        }
    )
    tokens = relationship(
        "OidcToken",
        back_populates="client",
        info={'colanderalchemy': {'exclude': True}}
    )
    authcodes = relationship(
        "OidcCode",
        back_populates="client",
        info={'colanderalchemy': {'exclude': True}}
    )

    def __init__(self,
                 name=None,
                 scopes=None,
                 admin_email=None,
                 logout_uri=None,
                 cert_salt=None):
        self.name = name
        self.admin_email = admin_email
        self.logout_uri = logout_uri
        self.salt = gen_salt()
        self.client_id = gen_client_id()
        self.client_secret = gen_client_secret()
        self.scopes = scopes
        if cert_salt:
            self.cert_salt = cert_salt

    def get_scopes(self):
        return self.scopes.split(' ')

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
        """
        Getter for the current client secret

        :returns: The client secret value
        :rtype: str
        """
        return self._client_secret

    def _crypt_secret(self, client_secret):
        """
        Returns a crypted version of the client_secret

        :param unicode client_secret: The clear client secret
        :returns: A crypted client secret
        :rtype: unicode
        """
        if isinstance(client_secret, unicode):
            client_secret = client_secret.encode('utf-8')
        client_secret = bytes(client_secret)
        return crypt_secret(client_secret, self.salt)

    def _set_client_secret(self, client_secret):
        """
        Define the client secret
        """
        self._client_secret = self._crypt_secret(client_secret)

    client_secret = synonym('_client_secret', descriptor=property(
        _get_client_secret, _set_client_secret))

    def revoke(self):
        """
        Revoke the given client
        """
        self.revoked = True
        self.revocation_date = datetime.datetime.utcnow()

    def is_revoked(self):
        """
        Check if the current client is still valid
        """
        return self.revoked

    def check_secret(self, client_secret):
        """
        Check that the given secret matches the current one

        :param str client_secret: The client secret transmitted by the Resource
        Consumer
        :param str salt: The salt used for encryption (see configuration)
        """
        encrypted = self._crypt_secret(client_secret)
        return encrypted == self.client_secret

    def check_scope(self, scopes):
        """
        Check that the scopes are allowed for the current client

        :param list scope: list of requested scopes
        :returns: True / False
        :rtype: bool
        """
        scopes = set(scopes)
        allowed_scopes = set(self.get_scopes())
        return scopes.issubset(allowed_scopes)


class OidcRedirectUri(DBBASE):
    __table_args__ = default_table_args
    id = Column(
        Integer,
        primary_key=True,
        info={'colanderalchemy': {'widget': deform.widget.HiddenWidget()}},
    )
    uri = Column(
        Unicode(255),
        nullable=False,
        unique=True,
        info={'colanderalchemy': {"title": u"Url"}}
    )

    client_id = Column(
        Integer,
        ForeignKey(OidcClient.id, ondelete='cascade'),
        info={'colanderalchemy': {'widget': deform.widget.HiddenWidget()}},
    )
    client = relationship(
        OidcClient,
        info={'colanderalchemy': {"exclude": True}},
    )

    def __init__(self, client=None, uri=None):
        self.client = client
        self.uri = uri


class OidcCode(DBBASE):
    __table_args__ = default_table_args
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=False)
    authcode = Column(Unicode(64), unique=True, nullable=False)
    uri = Column(Unicode(255), nullable=False)
    expires_in = Column(Integer, nullable=False, default=10*60)
    nonce = Column(Unicode(255))
    scopes = Column(Unicode(255))

    revoked = Column(Boolean, default=False)
    revocation_date = Column(DateTime)

    creation_date = Column(DateTime, default=datetime.datetime.utcnow)

    client_id = Column(Integer, ForeignKey(OidcClient.id))
    client = relationship(OidcClient)

    def __init__(self, client, user_id, uri, scopes):
        self.client = client
        self.user_id = user_id
        self.uri = uri
        self.scopes = scopes

        self.authcode = gen_token(self.client)

    def revoke(self):
        """
        Effectively set this instance as revoked
        """
        self.revoked = True
        self.revocation_date = datetime.datetime.utcnow()

    def is_revoked(self):
        """
        Check if the code is revoked or not

        :rtype: bool
        """
        if not self.revoked:
            expiry = self.creation_date + datetime.timedelta(
                minutes=self.expires_in
            )
            now = datetime.datetime.utcnow()
            if now > expiry:
                self.revoke()
                DBSESSION().merge(self)

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

    creation_date = Column(DateTime, default=datetime.datetime.utcnow)

    client_id = Column(Integer, ForeignKey(OidcClient.id))
    client = relationship(OidcClient)

    def __init__(self, client, user_id):
        self.client = client
        self.user_id = user_id

        self.access_token = gen_token(self.client)
        self.refresh_token = gen_token(self.client)

    def revoke(self):
        self.revoked = True
        self.revocation_date = datetime.datetime.utcnow()

    def is_revoked(self):
        """
        Check if the code is revoked or not

        :rtype: bool
        """
        if not self.revoked:
            expiry = self.creation_date + \
                datetime.timedelta(minutes=self.expires_in)

            now = datetime.datetime.utcnow()
            if now > expiry:
                self.revoke()
                DBSESSION().merge(self)
        return self.revoked

    def refresh(self):
        """
        Generate a new token for this client.
        """

        cls = self.__class__
        self.revoke()
        DBSESSION().merge(self)
        return cls(self.client, self.user_id)

    def __json__(self, request):
        token = {
            'token_type': 'Bearer',
            'access_token': self.access_token,
            'refresh_token': self.refresh_token,
            'expires_in': self.expires_in,
        }
        return token

    def at_hash(self):
        """
        Returns a "at_hash" as described here
        http://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken
        """
        return left_hash(self.access_token.encode("utf-8"), MAC)

    @classmethod
    def find(cls, token_str):
        token_query = cls.query().filter_by(access_token=token_str)
        token_query = token_query.filter_by(revoked=False)
        token = token_query.first()
        return token


class OidcIdToken(DBBASE):
    __table_args__ = default_table_args
    id = Column(Integer, primary_key=True)
    issuer = Column(Unicode(255), nullable=False)
    sub = Column(Unicode(255), nullable=False)
    expiration_time = Column(DateTime)
    issue_time = Column(DateTime)

    client_id = Column(Integer, ForeignKey(OidcClient.id))
    client = relationship(OidcClient)

    revoked = Column(Boolean, default=False)
    revocation_date = Column(DateTime)

    def __init__(self, issuer, client, code):
        self.client = client
        self.client_id = client.id
        self.sub = code.user_id
        self.issuer = issuer
        self.issue_time = datetime.datetime.utcnow()
        delta = datetime.timedelta(60)
        self.expiration_time = self.issue_time + delta

    def revoke(self):
        self.revoked = True
        self.revocation_date = datetime.datetime.utcnow()

    def is_revoked(self):
        if not self.revoked:
            now = datetime.datetime.utcnow()
            if self.expiration_time > now:
                self.revoke()
                DBSESSION().merge(self)
        return self.revoked

    @property
    def aud(self):
        return self.client.client_id

    def __json__(self, request, claims=None):
        result = {
            'iss': self.issuer,
            'sub': int(self.sub),
            'aud': self.aud,
            'exp': dt_to_timestamp(self.expiration_time),
            'iat': dt_to_timestamp(self.issue_time),
        }
        if claims is not None:
            for key, value in claims.iteritems():
                # We don't want to override the default openid scope datas
                if key not in result:
                    result[key] = value
        return result

    def _get_key_object(self, key):
        """
        Return the JWS Signing key, we simply use Symetrical keys based on the
        client_secret to sign the id token

        :param str key: The key used for encryption
        :rtype: obj
        :returns: A key object implementing jwkest.jwk.Key class
        """
        return SYMKey(key=key, alg=MAC)

    def __jwt__(self, request, claims, client_secret):
        """
        Jwt tokens encoded with the client_secret as key
        :param obj request; The pyramid request object
        :param dict claims: Dict containing userdatas that should be added to
        the current request (standard claims are described here :
        http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims )
        :param str client_secret: The original secret credential used to sign
        the JWT
        :returns: The ID token as a JWS as described in
        https://tools.ietf.org/html/rfc7515
        :rtype: str
        """
        json_datas = self.__json__(request, claims)
        _jws = JWS(json_datas, alg=MAC)
        return _jws.sign_compact([self._get_key_object(client_secret)])


def includeme(config):
    """
    void function used to ensure the models are added to the metadatas
    """
    pass
