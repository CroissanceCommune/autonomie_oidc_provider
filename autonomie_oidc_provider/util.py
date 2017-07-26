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

import base64
import logging
import calendar

from pyramid.threadlocal import get_current_registry
from autonomie_oidc_provider.exceptions import InvalidCredentials

logger = logging.getLogger(__name__)


def oidc_settings(key=None, default=None):
    """
    Get configuration from the current registry

    :param str key: The key to look for
    :param str default: The default value
    """
    settings = get_current_registry().settings

    if key:
        value = settings.get('oidc.%s' % key, default)
        if value == 'true':
            return True
        elif value == 'false':
            return False
        else:
            return value
    else:
        return dict((x.split('.', 1)[1], y) for x, y in settings.items()
                    if x.startswith('oidc.'))


def get_client_credentials(request):
    """
    Get the client credentials from the request headers

    :param obj request: Pyramid request object
    :returns: 2-uple (client_id, client_secret)
    :rtype: tuple

    :raises KeyError: When no Authorization header is present
    :raises InvalidCredentials: When credentials are not in basic format
    """
    if 'Authorization' in request.headers:
        auth = request.headers.get('Authorization')
    elif 'authorization' in request.headers:
        auth = request.headers.get('authorization')
    else:
        logger.error('No authorization header found')
        raise KeyError("No authorization header found")

    parts = auth.split()
    if len(parts) != 2:
        raise InvalidCredentials(
            error_description="Invalid authorization header"
        )

    token_type = parts[0].lower()
    if token_type != 'basic':
        logger.error("Unsupported authentication mechanism")
        raise InvalidCredentials(
            error_description="Unsupported authentication mechanism"
        )

    else:
        token = base64.b64decode(parts[1]).decode('utf8')

        client_id, client_secret = token.split(':')

    return client_id, client_secret


def dt_to_timestamp(datetime_obj):
    """
    Convert the given datetime_obj to an utc timestamp
    :param obj datetime_obj: An utc aware datetime object
    :returns: A timestamp
    """
    return calendar.timegm(datetime_obj.timetuple())
