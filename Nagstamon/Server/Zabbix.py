#!/usr/bin/python
# -*- encoding: utf-8; py-indent-offset: 4 -*-
# +------------------------------------------------------------------+
# |             ____ _               _        __  __ _  __           |
# |            / ___| |__   ___  ___| | __   |  \/  | |/ /           |
# |           | |   | '_ \ / _ \/ __| |/ /   | |\/| | ' /            |
# |           | |___| | | |  __/ (__|   <    | |  | | . \            |
# |            \____|_| |_|\___|\___|_|\_\___|_|  |_|_|\_\           |
# |                                                                  |
# | Copyright Mathias Kettner 2010             mk@mathias-kettner.de |
# |                                            lm@mathias-kettner.de |
# +------------------------------------------------------------------+
#
# The official homepage is at http://mathias-kettner.de/check_mk.
#
# check_mk is free software;  you can redistribute it and/or modify it
# under the  terms of the  GNU General Public License  as published by
# the Free Software Foundation in version 2.  check_mk is  distributed
# in the hope that it will be useful, but WITHOUT ANY WARRANTY;  with-
# out even the implied warranty of  MERCHANTABILITY  or  FITNESS FOR A
# PARTICULAR PURPOSE. See the  GNU General Public License for more de-
# ails.  You should have  received  a copy of the  GNU  General Public
# License along with GNU Make; see the file  COPYING.  If  not,  write
# to the Free Software Foundation, Inc., 51 Franklin St,  Fifth Floor,
# Boston, MA 02110-1301 USA.

# hax0rized by: lm@mathias-kettner.de

import sys
import urllib
import webbrowser
import traceback
import base64
import time
import datetime
from Nagstamon import Actions
from Nagstamon.Objects import *
from Nagstamon.Server.Generic import GenericServer
from Nagstamon.zabbix_api import ZabbixAPI, ZabbixAPIException
import pprint
pp = pprint.PrettyPrinter(indent=4)


class ZabbixError(Exception):
    def __init__(self, terminate, result):
        self.terminate = terminate
        self.result = result


class ZabbixServer(GenericServer):
    """
       special treatment for Check_MK Multisite JSON API
    """
    TYPE = 'Zabbix'
    zapi = None

    def __init__(self, **kwds):
        GenericServer.__init__(self, **kwds)
        self.States = ["UP", "UNKNOWN", "WARNING", "CRITICAL", "UNREACHABLE", "DOWN", "CRITICAL", "HIGH", "AVERAGE"]
        self.nagitems_filtered = {"services":
            {
                "CRITICAL": [],
                "HIGH": [],
                "AVERAGE": [],
                "WARNING": [],
                "INFORMATION": [], 
                "UNKNOWN": [],
                
                
                
            }, 
            "hosts":{
                "DOWN":[], 
                "UNREACHABLE":[]
                }
            }
        # Prepare all urls needed by nagstamon - 
        self.urls = {}
        self.statemap = {}

        # Entries for monitor default actions in context menu
        self.MENU_ACTIONS = ["Recheck", "Acknowledge", "Downtime"]
        self.username = self.conf.servers[self.get_name()].username
        self.password = self.conf.servers[self.get_name()].password
        self.min_severity = self.conf.servers[self.get_name()].min_severity

    def _login(self):
        try:
            self.zapi = ZabbixAPI(server=self.monitor_url, path="", log_level=0)
            self.zapi.login(self.username, self.password)
        except:
            result, error = self.Error(sys.exc_info())
            return Result(result=result, error=error)

    def init_HTTP(self):
        # Fix eventually missing tailing "/" in url
        self.statemap = {
            'UNREACH': 'UNREACHABLE',
            'CRIT': 'CRITICAL',
            'WARN': 'WARNING',
            'UNKN': 'UNKNOWN',
            'PEND': 'PENDING',
            '0': 'UNKNOWN',
            '1': 'INFORMATION',
            '2': 'WARNING',
            '3': 'AVERAGE',
            '4': 'HIGH',
            '5': 'CRITICAL'}
        GenericServer.init_HTTP(self)

    def _get_status(self):
        """
        Get status from Nagios Server
        """
        ret = Result()
        # create Nagios items dictionary with to lists for services and hosts
        # every list will contain a dictionary for every failed service/host
        # this dictionary is only temporarily
        nagitems = {"services": [], "hosts": []}

        # Create URLs for the configured filters
        if self.zapi is None:
            self._login()

        try:
            hosts = []
            hosts = self.zapi.host.get({"output": ["host", "ip", "status", "available", "error", "errors_from"], "filter": {}})


            for host in hosts:
                duration = int(time.time()) - int(host['errors_from'])
                n = {
                    'host': host['host'],
                    'hostid':host['hostid'],
                    'status': self.statemap.get(host['available'], host['available']),
                    'last_check': int(time.time()),
                    'duration': duration,
                    'status_information': host['error'],
                    'attempt': '0/0',
                    'site': '',
                    'address': host['host'],
                }

                # add dictionary full of information about this host item to nagitems
                nagitems["hosts"].append(n)
                # after collection data in nagitems create objects from its informations
                # host objects contain service objects
                if n["host"] not in self.new_hosts:
                    new_host = n["host"]
                    self.new_hosts[new_host] = GenericHost()
                    self.new_hosts[new_host].name = n["host"]
                    self.new_hosts[new_host].hostid = n["hostid"]
                    self.new_hosts[new_host].status = n["status"]
                    self.new_hosts[new_host].last_check = n["last_check"]
                    self.new_hosts[new_host].duration = n["duration"]
                    self.new_hosts[new_host].attempt = n["attempt"]
                    self.new_hosts[new_host].status_information = n["status_information"]
                    self.new_hosts[new_host].site = n["site"]
                    self.new_hosts[new_host].address = n["address"]
                    # transisition to Check_MK 1.1.10p2
                    if 'host_in_downtime' in host:
                        if host['host_in_downtime'] == 'yes':
                            self.new_hosts[new_host].scheduled_downtime = True
                    if 'host_acknowledged' in host:
                        if host['host_acknowledged'] == 'yes':
                            self.new_hosts[new_host].acknowledged = True

        except:
            result, error = self.Error(sys.exc_info())
            self.isChecking = False
            return Result(result=result, error=error)

        # services
        services = []
        groupids = []
        zabbix_triggers = []
        try:
            response = []
            try:
                choosed_groups = {}
                exception_set = {}
                hostgroup_ids = {}
                zparams = {
                    'only_true': True,
                    'output': ['triggerid', 'state', 'error', 'url', 'expression', 'description', 'priority', 'lastchange'],
                    'selectHosts': ['hostid', 'name'],
                    'selectGroups': ['groupid', 'name'],
                    'selectLastEvent': ['eventid', 'acknowledged', 'objectid', 'clock', 'ns'],
                    'sortfield': ['priority', 'lastchange'],
                    'sortorder': 'DESC',
                    'skipDependent': True,
                    'maintenance': False,
                    'withUnacknowledgedEvents': True,
                    'monitored': True,
                    'expandDescription': True,
                    'active': True,
                    'min_severity': self.min_severity,
                    'expandData': True,
                    'filter': {'priority': [1,2,3,4,5], 'value': 1}
                    }
                if self.monitor_cgi_url:
                    group_list = {x.strip() for x in self.monitor_cgi_url.split(',')}
                    all_groups = {int(x.get('groupid')) for x in self.zapi.hostgroup.get({'with_monitored_triggers': True})}
                    if '!' in self.monitor_cgi_url:
                        exception_set = {int(x.get('groupid')) for x in self.zapi.hostgroup.get({
                            'with_monitored_items': True,
                            'output': 'extend',
                            'filter': {'name': [x[1:] for x in group_list if x.startswith('!')]}}) if int(x.get('internal')) == 0}
                    else:
                        exception_set = set()

                    hostgroup_ids = {int(x['groupid']) for x in self.zapi.hostgroup.get(
                        {'output': 'extend',
                         'with_monitored_items': True,
                         'filter': {'name': [x for x in group_list if not x.startswith('!')]}}) if int(x['internal']) == 0}
                    if len(hostgroup_ids):
                        choosed_groups = (all_groups & hostgroup_ids) - exception_set
                    else:
                        choosed_groups = all_groups - exception_set
                    zparams['groupids'] = list(choosed_groups)

                zabbix_triggers = self.zapi.trigger.get(zparams)
                result_list = []
                if choosed_groups:
                    for x in zabbix_triggers:
                        allowed = True
                        for y in x.get('groups'):
                            if int(y.get('groupid')) in exception_set:
                                allowed = False
                        if allowed:
                            result_list.append(x)
                else:
                    result_list = zabbix_triggers

                if type(result_list) is dict:
                    for triggerid in result_list.keys():
                        services.append(result_list[triggerid])
                elif type(result_list) is list:
                    for trigger in result_list:
                        services.append(trigger)

            except:
                result, error = self.Error(sys.exc_info())
                self.isChecking = False
                return Result(result=result, error=error)

            for service in services:
                try:
                    if len(service['items'][0]['key_'])>50:
                        service['items'][0]['key_'] = '%s...' % service['items'][0]['key_'][0:50]

                    state = '%s=%s' % (service['items'][0]['key_'], service['items'][0]['lastvalue'])
                except:
                    state = '%s' % (service['description'])
                host_api_details = self.zapi.host.get({'hostids': [service['hostid']],
                                                       'selectGroups': 'extend',
                                                       'monitored_hosts': True,
                                                       'output': 'extend'})
                groups = None
                #print host_api_details
                if host_api_details[0].get('groups'):
                    groups = ','.join([x['name'] for x in host_api_details[0]['groups']])
                else:
                    host_api_details = self.zapi.host.get({'hostids': [service['hostid']],
                                                           'select_groups': 'extend',
                                                           'monitored_hosts': True,
                                                           'output': 'extend'})
                    groups = ",".join([x['name'] for x in host_api_details[0]['groups']])
                n = {
                    'host': service['host'],
                    'hostid': service['hostid'],
                    'service': service['description'],
                    'status': self.statemap.get(service['priority'], service['priority']),
                    'attempt': '0/0',
                    'duration': groups,
                    'status_information': state,
                    'passiveonly': 'no',
                    'last_check': datetime.datetime.fromtimestamp(int(service['lastchange'])),
                    'notifications': 'yes',
                    'flapping': 'no',
                    'site': '',
                    'command': 'zabbix',
                    'triggerid': service['triggerid'],
                }
                nagitems["services"].append(n)
                # after collection data in nagitems create objects of its informations
                # host objects contain service objects
                if n["host"] not in  self.new_hosts:
                    self.new_hosts[n["host"]] = GenericHost()
                    self.new_hosts[n["host"]].name = n["host"]
                    self.new_hosts[n["host"]].status = "UP"
                    self.new_hosts[n["host"]].site = n["site"]
                    self.new_hosts[n["host"]].address = n["host"]
                    # if a service does not exist create its object
                if n["service"] not in  self.new_hosts[n["host"]].services:
                    new_service = n["service"]
                    self.new_hosts[n["host"]].services[new_service] = GenericService()
                    self.new_hosts[n["host"]].services[new_service].host = (n["host"])
                    self.new_hosts[n["host"]].services[new_service].hostid = n["hostid"]
                    self.new_hosts[n["host"]].services[new_service].name = n["service"]
                    self.new_hosts[n["host"]].services[new_service].status = n["status"]
                    self.new_hosts[n["host"]].services[new_service].last_check = n["last_check"]
                    self.new_hosts[n["host"]].services[new_service].duration = n["duration"]
                    self.new_hosts[n["host"]].services[new_service].attempt = n["attempt"]
                    self.new_hosts[n["host"]].services[new_service].status_information = n["status_information"]
                    self.new_hosts[n["host"]].services[new_service].passiveonly = n["passiveonly"]
                    self.new_hosts[n["host"]].services[new_service].flapping = n["flapping"]
                    self.new_hosts[n["host"]].services[new_service].site = n["site"]
                    self.new_hosts[n["host"]].services[new_service].address = n["host"]
                    self.new_hosts[n["host"]].services[new_service].command = n["command"]
                    self.new_hosts[n["host"]].services[new_service].triggerid = n["triggerid"]

                    if 'svc_in_downtime' in service:
                        if service['svc_in_downtime'] == 'yes':
                            self.new_hosts[n["host"]].services[new_service].scheduled_downtime = True
                    if 'svc_acknowledged' in service:
                        if service['svc_acknowledged'] == 'yes':
                            self.new_hosts[n["host"]].services[new_service].acknowledged = True
                    if 'svc_is_active' in service:
                        if service['svc_is_active'] == 'no':
                            self.new_hosts[n["host"]].services[new_service].passiveonly = True
                    if 'svc_flapping' in service:
                        if service['svc_flapping'] == 'yes':
                            self.new_hosts[n["host"]].services[new_service].flapping = True
        except:
            # set checking flag back to False
            self.isChecking = False
            result, error = self.Error(sys.exc_info())
            print sys.exc_info()
            return Result(result=result, error=error)
        return ret

    def _open_browser(self, url):
        webbrowser.open(url)

        if str(self.conf.debug_mode) == "True":
            self.Debug(server=self.get_name(), debug="Open web page " + url)

    def open_services(self):
        self._open_browser(self.urls['human_services'])

    def open_hosts(self):
        self._open_browser(self.urls['human_hosts'])

    def open_tree_view(self, host, service=""):
        """
        open monitor from treeview context menu
        """

        if service == "":
            url = self.urls['human_host'] + urllib.urlencode(
                {'x': 'site=' + self.hosts[host].site + '&host=' + host}).replace('x=', '%26')
        else:
            url = self.urls['human_service'] + urllib.urlencode(
                {'x': 'site=' + self.hosts[host].site + '&host=' + host + '&service=' + service}).replace('x=', '%26')

        if str(self.conf.debug_mode) == "True":
            self.Debug(server=self.get_name(), host=host, service=service,
                       debug="Open host/service monitor web page " + url)
        webbrowser.open(url)

    def GetHostId(self, host):
        """
        find out ip or hostname of given host to access hosts/devices which do not appear in DNS but
        have their ip saved in Nagios
        """

        # the fasted method is taking hostname as used in monitor

        hostid = ""

        try:
            if host in self.hosts:
                hostid = self.hosts[host].hostid


        except ZabbixError:
            result, error = self.Error(sys.exc_info())
            return Result(result=result, error=error)

        return Result(result=hostid)

    def _set_recheck(self, host, service):
        pass

    def get_start_end(self, host):
        return time.strftime("%Y-%m-%d %H:%M"), time.strftime("%Y-%m-%d %H:%M", time.localtime(time.time() + 7200))

    def _action(self, site, host, service, specific_params):
        params = {
            'site': self.hosts[host].site,
            'host': host,
        }
        params.update(specific_params)

        if self.zapi is None:
            self._login()
        events = []
        for e in self.zapi.event.get({'triggerids': params['triggerids'],
                                      'hide_unknown': True}):
            events.append(e['eventid'])
        self.zapi.event.acknowledge({'eventids': events, 'message': params['message']})

    def _set_downtime(self, host, service, author, comment, fixed, start_time, end_time, hours, minutes):
        pass

    def _set_acknowledge(self, host, service, author, comment, sticky, notify, persistent, all_services=[]):
        triggerid = self.hosts[host].services[service].triggerid
        p = {
            'message': '%s: %s' % (author, comment),
            'triggerids': [triggerid],
        }
        self._action(self.hosts[host].site, host, service, p)

        # acknowledge all services on a host when told to do so
        for s in all_services:
            self._action(self.hosts[host].site, host, s, p)
