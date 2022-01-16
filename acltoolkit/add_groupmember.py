import argparse
import logging
import ldap3

from acltoolkit.ldap import LDAPConnection, LDAPEntry
from acltoolkit.target import Target

class AddGroupMember:
    def __init__(self, options: argparse.Namespace):
        self.options = options

        self.target = Target(options)

        self._user = None
        self._group = None

        self.ldap_connection = None

    def connect(self):
        self.ldap_connection = LDAPConnection(self.options.scheme, self.target)
        self.ldap_connection.connect()

    def search(self, *args, **kwargs) -> 'list["LDAPEntry"]':
        return self.ldap_connection.search(*args, **kwargs)

    def write(self, *args, **kwargs) -> int:
        return self.ldap_connection.write(*args, **kwargs)

    def run(self):
        self.connect()
        logging.info("Will add %s to %s group" % (self.user.get("distinguishedName"), self.group.get("distinguishedName")))

        ret = self.write(self.group.get("distinguishedName"),  {'member': [(ldap3.MODIFY_ADD, [self.user.get("distinguishedName")])]})
        if ret['result'] == 0:
            logging.info("Object Owner modified successfully !")
        else :
            if ret['result'] == 50:
                raise Exception('Could not modify object, the server reports insufficient rights: %s', ret['message'])
            elif ret['result'] == 19:
                raise Exception('Could not modify object, the server reports a constrained violation: %s', ret['message'])
            else:
                raise Exception('The server returned an error: %s', ret['message'])



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
            attributes=["objectSid", "distinguishedName", "nTSecurityDescriptor", "primaryGroupId"],
        )

        if len(users) == 0:
            raise Exception("Could not find user with account name: %s" % username)

        self._user = users[0]

        return self._user

    @property
    def group(self) -> 'list["LDAPEntry"]':
        if self._group is not None:
            return self._group

        groupname = self.options.group
        groups = self.search(
            "(&(objectclass=group)(name=%s))" % groupname,
            attributes=["objectSid", "distinguishedName"],
        )

        if len(groups) == 0:
            raise Exception("Could not find group with name: %s" % groupname)

        self._group = groups[0]

        return self._group

def add_groupmember(options: argparse.Namespace):
    g = AddGroupMember(options)
    g.run()