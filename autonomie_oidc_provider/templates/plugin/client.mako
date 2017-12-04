<%doc>
    * Copyright (C) 2012-2016 Croissance Commune
 * Authors:
       * Arezki Feth <f.a@majerti.fr>;
       * Miotte Julien <j.m@majerti.fr>;
       * TJEBBES Gaston <g.t@majerti.fr>

 This file is part of Autonomie : Progiciel de gestion de CAE.

    Autonomie is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Autonomie is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Autonomie.  If not, see <http://www.gnu.org/licenses/>.
</%doc>
<%inherit file="${context['main_template'].uri}" />
<%block name='content'>
<div class='panel panel-default page-block'>
    <div class='panel-heading'>
        Application autorisée
    </div>
    <div class='panel-body'>
        <h3>${_context.name}</h3>
        <a
            class='btn btn-primary primary-action'
            href="${request.current_route_path(_query={'action': 'edit'})}"
            >
            <i class='fa fa-pencil'></i>&nbsp;Modifier ces informations
        </a>
        <a
            href="${request.current_route_path(_query={'action': 'revoke'})}"
            class='btn btn-default secondary-action'
            onclick="return confirm('Cette application ne pourra plus accéder \
à Autonomie. Continuer ?')"
            >
            <i class='fa fa-archive'></i>&nbsp;Révoquer les droits de cette application
        </a>
        <a
            href="${request.current_route_path(_query={'action': 'refresh_secret'})}"
            class='btn btn-default secondary-action'
            onclick="return confirm('Cette application ne pourra plus accéder \
à Autonomie avec ses anciens identifiants. Continuer ?')"
            >
            <i class='fa fa-refresh'></i>&nbsp;Générer un nouveau code de connexion
        </a>
        <hr />
        % if _context.revoked:
        <div class='alert alert-danger'>
        <i class='fa fa-warning'></i>&nbsp;Les droits de cette application
        ont été révoqués le ${api.format_date(_context.revocation_date)}
        </div>
        % endif
        <p>Client ID : ${_context.client_id}</p>
        <p>Urls de redirection déclarées
            <ul>
                % for redirect_uri in _context.redirect_uris:
                <li>${redirect_uri.uri}</li>
                % endfor
            </ul>
        </p>
        <p>Autorisations dont bénéficie l'application
            <ul>
                % for scope in _context.get_scopes():
                    <li>${api.format_scope(scope)}</li>
                % endfor
            </ul>
        </p>
    </div>
</div>
</%block>
