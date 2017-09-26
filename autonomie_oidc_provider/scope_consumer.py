# -*- coding: utf-8 -*-
# * Authors:
#       * TJEBBES Gaston <g.t@majerti.fr>
#       * Arezki Feth <f.a@majerti.fr>;
#       * Miotte Julien <j.m@majerti.fr>;
import datetime

from autonomie_base.utils.date import format_short_date

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
        res[key] = [format_res_for_encoding(i) for i in val]
    elif type(res) in FORMATTERS:
        res = FORMATTERS[type(res)](res)

    return res


class Scope(object):
    key = None
    attributes = ()

    def produce(self, user_object):
        res = {}
        for label, data_key in self.attributes:
            if data_key:
                data_value = getattr(user_object, data_key, '')
                if hasattr(data_value, '__json__'):
                    data_value = data_value.__json__(None)

                res[label] = data_value
            else:
                # Not implemented
                res[label] = ''
        res = format_res_for_encoding(res)
        return res


class OpenIdScope(Scope):
    key = 'openid'
    attributes = (
        ('user_id', 'id'),
    )


class ProfileScope(Scope):
    key = 'profile'
    attributes = (
        ('name', 'label'),
        ('firstname', 'firstname'),
        ('lastname', 'lastname'),
        ('email', 'email'),
        ('login', 'login'),
        # ('groups', 'groups'),
    )
