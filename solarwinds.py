from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
    name: solarwinds
    author:
        - Austin de Coup-Crank (@austind)
    short_description: Ansible dynamic inventory plugin for SolarWinds Orion NPM.
    requirements:
        - python >= 3.6
        - orionsdk >= 0.3.0
    extends_documentation_fragment:
        - constructed
    options:
        plugin:
            description: marks this as an instance of the 'solarwinds' plugin
            required: true
            choices: ['solarwinds', 'community.solarwinds.orion']
        server:
            description: IP address or FQDN of SolarWinds server
            required: true
            env:
                - name: SOLARWINDS_SERVER
        username:
            description: SolarWinds username
            required: true
            env:
                - name: SOLARWINDS_USERNAME
        password:
            description: SolarWinds password
            required: true
            env:
                - name: SOLARWINDS_PASSWORD
        validate_certs:
            description: Whether or not to validate the cert presented by server
            required: true
"""

EXAMPLES = r"""
    TODO
"""

import os
import re

from ansible.errors import AnsibleError, AnsibleParserError
from ansible.module_utils.six import string_types
from ansible.plugins.inventory import BaseInventoryPlugin, Constructable

try:
    from orionsdk import SwisClient

    HAS_ORIONSDK = True
except ImportError:
    HAS_ORIONSDK = False


class InventoryModule(BaseInventoryPlugin, Constructable):

    NAME = "solarwinds"

    def _build_client(self):
        """ Build SWIS client """

        server = self.get_option("server")
        username = self.get_option("username")
        password = self.get_option("password")

        if server is None:
            try:
                server = os.environ["SOLARWINDS_SERVER"]
            except KeyError:
                pass

        if username is None:
            try:
                username = os.environ["SOLARWINDS_USERNAME"]
            except KeyError:
                pass

        if password is None:
            try:
                password = os.environ["SOLARWINDS_PASSWORD"]
            except KeyError:
                pass

        if server is None:
            raise AnsibleError(
                "Could not find SolarWinds server from plugin config or environment"
            )

        if username is None:
            raise AnsibleError(
                "Could not find Solarwinds username from plugin config or environment"
            )

        if password is None:
            raise AnsibleError(
                "Could not find SolarWinds password from plugin config or environment"
            )

        if not self.get_option("validate_certs"):
            import requests
            from requests.packages.urllib3.exceptions import InsecureRequestWarning
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

        self.display.vvv(f"Connecting to {server} as {username}")
        self.client = SwisClient(server, username, password)


    def _get_hosts(self):
        query = "SELECT N.NodeID AS id, N.Caption AS hostname, N.IPAddress AS ipaddress, N.CustomProperties.School_District AS district, N.CustomProperties.School_Site AS site FROM Orion.Nodes N WHERE N.CustomProperties.DeviceClass = 'Network' AND N.Vendor = 'Cisco'"
        result = self.client.query(query)
        self.hosts = result["results"]
        self.display.vvv(f"Retrieved {len(self.hosts)} hosts from SolarWinds NPM")

    def _format_host_name(self, host):
        """ Formats host name """
        return re.sub(r'_','-', host)

    def _format_group_name(self, item):
        """ Formats group name """
        item = item.lower()
        item = re.sub(r'[^A-Za-z0-9\-]', '_', item)
        return item

    def _add_groups(self):
        """ Add groups to dynamic inventory """
        self.solarwinds_groups = set(
            filter(None, [
                host['district']
                for host
                in self.hosts
            ])
        )

        for group in self.solarwinds_groups:
            self.inventory.add_group(self._format_group_name(group))

    def _add_hosts_to_groups(self):
        """ Add hosts to groups """
        for host in self.hosts:
            self.inventory.add_host(self._format_host_name(host['hostname']), group=self._format_group_name(host['district']))

    def verify_file(self, path):
        """ Verify SolarWinds config file """
        if super(InventoryModule, self).verify_file(path):
            endings = ("solarwinds.yaml", "solarwinds.yml")
            if any((path.endswith(ending) for ending in endings)):
                return True
        return False


    def parse(self, inventory, loader, path, cache=True):
        """ Parse SolarWinds Orion inventory """
        super(InventoryModule, self).parse(inventory, loader, path)

        if not HAS_ORIONSDK:
            raise AnsibleError(
                "The SolarWinds Orion dynamic inventory plugin requires the orionsdk module."
            )

        config_data = self._read_config_data(path)
        self._build_client()

        self._get_hosts()
        self._add_groups()
        self._add_hosts_to_groups()

