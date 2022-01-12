import argparse
import logging

from ldap3.protocol.formatters.formatters import format_sid
from ldap3.protocol.microsoft import security_descriptor_control

from acltlk.ldap import LDAPConnection, LDAPEntry
from acltlk.target import Target

from acltlk.constants import ACTIVE_DIRECTORY_RIGHTS, ACCESS_CONTROL_TYPE, EXTENDED_RIGHTS_MAP, EXTENDED_RIGHTS_NAME_MAP


class Get:
    def __init__(self, options: argparse.Namespace):
        self.options = options

        self.target = Target(options)
        self._domain = None
        self._user = None
        self._user_sids = None
        self._groups = None
        self._sid_map = {}

        self.ldap_connection = None

    def connect(self):
        self.ldap_connection = LDAPConnection(self.target)
        self.ldap_connection.connect()

    def search(self, *args, **kwargs) -> 'list["LDAPEntry"]':
        return self.ldap_connection.search(*args, **kwargs)

    def run(self):
        self.connect()

    def sid_lookup(self, sid: str) -> str:
        results = self.search(
            "(&(objectSid=%s)(|(objectClass=group)(objectClass=user)))" % sid,
            attributes=["name", "objectSid"],
        )

        if len(results) == 0:
            return sid
        
        result = results[0]

        self._sid_map[sid] = "%s\\%s" % (self.domain.get("name"),result.get("name"))
        return self._sid_map[sid]
    
    @property
    def domain(self) -> str:
        if self._domain is not None:
            return self._domain

        domains = self.search(
            "(&(objectClass=domain)(distinguishedName=%s))"
            % self.ldap_connection.root_name_path,
            attributes=["name"],
        )
        if len(domains) == 0:
            logging.debug(
                    "Could not find domain root domain %s, trying default %s" 
                    % (self.ldap_connection.root_name_path, self.ldap_connection.default_path)
                    )

            domains = self.search(
                "(&(objectClass=domain)(distinguishedName=%s))"
                % self.ldap_connection.default_path,
                attributes=["name"],
            )

            if len(domains) == 0:
                raise Exception(
                    "Could not find domains: %s and %s" 
                    % (self.ldap_connection.root_name_path,
                    self.ldap_connection.default_path)
                )

        self._domain = domains[0]

        return self._domain

    @property
    def user(self) -> LDAPEntry:
        if self._user is not None:
            return self._user

        if self.options.user is not None:
            username = self.options.user
        else:
            username = self.target.username

        users = self.search(
            "(&(objectclass=user)(sAMAccountName=%s))" % username,
            attributes=["objectSid", "distinguishedName"],
        )

        if len(users) == 0:
            raise Exception("Could not find user with account name: %s" % username)

        self._user = users[0]

        return self._user

    @property
    def groups(self) -> 'list["LDAPEntry"]':
        if self._groups is not None:
            return self._groups

        self._groups = self.search(
            "(member:1.2.840.113556.1.4.1941:=%s)" % self.user.get("distinguishedName"),
            attributes="objectSid",
        )

        return self._groups

    @property
    def user_sids(self) -> 'list[str]':
        """List of effective SIDs for user"""
        if self._user_sids is not None:
            return self._user_sids

        self._user_sids = list(
            map(
                lambda entry: format_sid(entry.get_raw("objectSid")),
                [*self.groups, self.user],
            )
        )

        return self._user_sids


def get(options: argparse.Namespace):
    g = Get(options)
    g.run()