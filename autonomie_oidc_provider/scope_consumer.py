# -*- coding: utf-8 -*-
# * Authors:
#       * TJEBBES Gaston <g.t@majerti.fr>
#       * Arezki Feth <f.a@majerti.fr>;
#       * Miotte Julien <j.m@majerti.fr>;
import datetime

from autonomie_base.utils.date import format_short_date
from autonomie.models.user.user import User

FORMATTERS = {
    long: int,
    datetime.date: format_short_date,
    datetime.datetime: format_short_date
}


def format_res_for_encoding(res):
    if isinstance(res, dict):
        for key, val in res.items():
            res[key] = format_res_for_encoding(val)
    elif isinstance(res, (tuple, list)):
        res = [format_res_for_encoding(i) for i in res]
    elif type(res) in FORMATTERS:
        res = FORMATTERS[type(res)](res)

    return res


class Scope(object):
    key = None
    attributes = ()

    def _produce_from_dotted_key(self, data_key, user_object):
        """
        Produce an attribute's value based on a dotted data key (that allows to
        access related elements)
        """
        path = data_key.split('.')
        data = user_object
        for segment in path:
            data = getattr(data, segment, None)
        data = self._process_complex_value(data)
        return data

    def _process_serializable_object(self, data):
        result = data
        if hasattr(data, '__json__'):
            result = data.__json__(None)
        return result

    def _process_list_value(self, data):
        result = []
        for d in data:
            result.append(self._process_serializable_object(d))
        return result

    def _process_complex_value(self, data):
        """
        Process specific case of complex datas
        :param data: The data to process
        """
        if isinstance(data, list):
            data = self._process_list_value(data)
        else:
            data = self._process_serializable_object(data)
        return data

    def produce(self, user_object):
        res = {}
        for label, data_key in self.attributes:
            if data_key:
                if '.' in data_key:
                    data_value = self._produce_from_dotted_key(
                        data_key,
                        user_object
                    )
                else:
                    data_value = getattr(user_object, data_key, '')
                    data_value = self._process_complex_value(data_value)
                res[label] = data_value
            else:
                # Not implemented
                res[label] = ''
        res = format_res_for_encoding(res)
        return res


class OpenIdScope(Scope):
    key = 'openid'
    attributes = (
        ('sub', 'id'),
    )


class ProfileScope(Scope):
    key = 'profile'
    attributes = (
        ('user_id', 'id'),
        ('name', 'label'),
        ('firstname', 'firstname'),
        ('lastname', 'lastname'),
        ('email', 'email'),
        ('login', 'login.login'),
        ('groups', '_groups'),
    )


def collect_claims(user_id, scopes):
    """
    Collect the claims described by the requested scopes for the given user_id

    :param int user_id: The id of the user
    :param list scopes: The list of scopes we want to collect claims for
    :returns: The claims
    :rtype: dict
    """
    result = {}
    user = User.get(user_id)
    for scope in scopes:
        if scope == 'profile':
            factory = ProfileScope()
            result.update(factory.produce(user))
        elif scope == 'openid':
            factory = OpenIdScope()
            result.update(factory.produce(user))
    return result
