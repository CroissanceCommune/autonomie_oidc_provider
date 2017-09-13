#
# Copyright (c) Elliot Peele <elliot@bentlogic.net>
#
# This program is distributed under the terms of the MIT License as found
# in a file called LICENSE. If it is not present, the license
# is always available at http://www.opensource.org/licenses/mit-license.php.
#
# This program is distributed in the hope that it will be useful, but
# without any warrenty; without even the implied warranty of merchantability
# or fitness for a particular purpose. See the MIT License for full details.
#

import sys
import time
import random
import hashlib

if getattr(hashlib, 'pbkdf2_hmac', None) is None:
    try:
        from backports.pbkdf2 import pbkdf2_hmac
    except:
        print("Install https://pypi.python.org/pypi/backports.pbkdf2/")
        sys.exit(1)
    hash_tool = pbkdf2_hmac
else:
    hash_tool = hashlib.pbkdf2_hmac

from base64 import b64encode
import binascii

def _get_hash():
    """
    Hash generation

    :rtype: str
    """
    sha = hashlib.sha256()
    sha.update(str(random.random()).encode('utf8'))
    sha.update(str(time.time()).encode('utf8'))
    return sha

def gen_salt():
    """
    Generates a random salt str

    :returns: a salt string
    :rtype: str
    """
    return _get_hash().hexdigest()


def gen_client_id():
    """
    Generates a random client id

    :returns: A token
    :rtype: str
    """
    return _get_hash().hexdigest()

def gen_client_secret():
    """
    Generates a random client secret key

    :returns: A token
    :rtype: str
    """
    return _get_hash().hexdigest()

def gen_token(client):
    """
    Generates a random token for the given client

    :param obj client: An OidcClient instance
    :returns: A token
    :rtype: str
    """
    sha = _get_hash()
    sha.update(client.client_id.encode('utf8'))
    return sha.hexdigest()

def crypt_secret(secret, salt):
    """
    Derive the secret key with the given salt

    :param bytes secret: The secret key
    :param str salt: The salt to use for derivation
    :returns: The encrypted secret
    :rtype: str
    """
    assert isinstance(secret, bytes)
    salt = b64encode(salt.encode('utf-8'))
    hash_ = hash_tool('sha256', secret, salt, 100000)
    return binascii.hexlify(hash_)
