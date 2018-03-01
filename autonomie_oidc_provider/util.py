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

from six.moves.urllib.parse import (
    urlparse,
    ParseResult,
    urlencode,
    parse_qsl,
)

from autonomie_oidc_provider.exceptions import (
    InvalidCredentials,
    InvalidRequest,
)

logger = logging.getLogger(__name__)


def oidc_settings(settings, key=None, default=None):
    """
    Get configuration from the current registry

    :param dict settings; The current settings
    :param str key: The key to look for
    :param str default: The default value
    """
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
    elif 'client_id' in request.POST and 'client_secret' in request.POST:
        return request.POST['client_id'], request.POST['client_secret']
    else:
        logger.error('No authorization header found')
        logger.error(request.headers.items())
        raise InvalidRequest(error_description="No authorization header found")

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


def get_access_token(request):
    """
    Retrieve the access token provided in the request headers

    Only handle Authorization headers

    :param obj request: The Pyramid request object
    :returns: An Access token
    """

    if 'Authorization' in request.headers:
        auth = request.headers.get('Authorization')
    elif 'authorization' in request.headers:
        auth = request.headers.get('authorization')
    else:
        logger.error('No authorization header found')
        logger.error(request.headers.items())
        raise InvalidRequest(error_description="No authorization header found")

    parts = auth.split()
    if len(parts) != 2:
        raise InvalidCredentials(
            error_description="Invalid authorization header "
            "(not a bearer token)"
        )

    token_type = parts[0].lower()
    if token_type != 'bearer':
        logger.error("Unsupported token format")
        raise InvalidCredentials(
            error_description="Unsupported token format",
        )
    else:
        token = parts[1].strip()
    return token


def add_get_params(url, params):
    """
    Add get params to an existing url (that may contain params)

    :param str url: The original url
    :param dict params: The dictionnary of {key:param} to add to the url
    :returns: An update url
    :rtype: str
    """
    url_obj = urlparse(url)
    query_params = dict(parse_qsl(url_obj.query))
    query_params.update(params)
    url = ParseResult(
        url_obj.scheme,
        url_obj.netloc,
        url_obj.path,
        url_obj.params,
        urlencode(query_params),
        ''
    )
    return url.geturl()
