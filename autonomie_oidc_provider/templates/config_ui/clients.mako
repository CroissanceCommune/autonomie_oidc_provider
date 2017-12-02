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
<%namespace file="/base/utils.mako" import="dropdown_item"/>
<%namespace file="/base/pager.mako" import="pager"/>
<%namespace file="/base/pager.mako" import="sortable"/>
<%block name='afteractionmenu'>
<div class='page-header-block'>
<a class='btn btn-primary primary-action'
    href="${request.route_path('/oidc_config/clients', _query={'action': 'add'})}"
    >
    Ajouter une application
</a>
</div>
</%block>
<%block name='content'>
<div class='panel panel-default page-block'>
    <div class='panel-heading'>
        <a  href='#filter-form'
            data-toggle='collapse'
            aria-expanded="false"
            aria-controls="filter-form">
            <i class='glyphicon glyphicon-search'></i>&nbsp;
            Filtres&nbsp;
            <i class='glyphicon glyphicon-chevron-down'></i>
        </a>
        % if '__formid__' in request.GET:
            <div class='help-text'>
                <small><i>Des filtres sont actifs</i></small>
            </div>
            <div class='help-text'>
                <a href="${request.current_route_path(_query={})}">
                    <i class='glyphicon glyphicon-remove'></i> Supprimer tous les filtres
                </a>
            </div>
        % endif
    </div>
    <div class='panel-body'>
        <div class='collapse' id='filter-form'>
            <div class='row'>
                <div class='col-xs-12'>
                    ${form|n}
                </div>
            </div>
        </div>
    </div>
</div>
<div class='panel panel-default page-block'>
    <div class='panel-heading'>
        ${records.item_count} Résultat(s)
    </div>
    <div class='panel-body'>
        <table class="table table-striped table-condensed table-hover">
            <thead>
                <tr>
                    <th>${sortable(u"Application", "name")}</th>
                    <th>Client ID</th>
                    <th>Autorisation (scopes)</th>
                    <th>Urls de redirection</th>
                    <th class="actions">Actions</th>
                </tr>
            </thead>
            <tbody>
                % if records:
                    % for client in records:
                    <tr class='tableelement'>
                        <td>
                            % if client.revoked:
                            <span class='label label-warning'>
                            Cette application a été révoquée
                            </span>
                            % endif
                            ${client.name}
                        </td>
                        <td>
                            ${client.client_id}
                        </td>
                        <td>
                            <ul>
                                % for scope in client.get_scopes():
                                    <li>
                                    ${scope}
                                    </li>
                                % endfor
                            </ul>
                        </td>
                        <td>
                            <ul>
                                % for redirect_uri in client.redirect_uris:
                                    <li>
                                    ${redirect_uri.uri}
                                    </li>
                                % endfor
                            </ul>
                        </td>
                        <td class='text-right'>
                            <div class='btn-group'>
                                <button
                                    type="button"
                                    class="btn btn-default dropdown-toggle"
                                    data-toggle="dropdown"
                                    aria-haspopup="true"
                                    aria-expanded="false">
                                    Actions <span class="caret"></span>
                                </button>
                                <ul class="dropdown-menu dropdown-menu-right">
                                    % for url, label, title, icon, options in stream_actions(client):
                                        ${dropdown_item(url, label, title, icon=icon, **options)}
                                    % endfor
                                </ul>
                            </div>
                        </td>
                    </tr>
                    % endfor
                % else:
                    <tr>
                        <td colspan='6'>
                            Aucue application n'a été créée pour l'instant
                        </td>
                    </tr>
                % endif
            </tbody>
        </table>
        ${pager(records)}
    </div>
</div>
</%block>
<%block name='footerjs'>
$(function(){
        $('input[name=search]').focus();
});
</%block>
