import argparse
import logging

import ldap3
from ldap3.protocol.microsoft import security_descriptor_control
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR, LDAP_SID

from acltoolkit.ldap import LDAPConnection, LDAPEntry, SecurityInformation, DEFAULT_CONTROL_FLAGS
from acltoolkit.target import Target
from acltoolkit.constants import WELL_KNOWN_SIDS

class SetObjectOwner:
    def __init__(self, options: argparse.Namespace):
        self.options = options

        self.target = Target(options)
        self._domain = None
        self._object = None
        self._owner = None

        self.ldap_connection = None

        self._security_descriptor = None

    def connect(self):
        self.ldap_connection = LDAPConnection(self.options.scheme, self.target)
        self.ldap_connection.connect()

    def search(self, *args, **kwargs) -> 'list["LDAPEntry"]':
        return self.ldap_connection.search(*args, **kwargs)

    def write(self, *args, **kwargs) -> int:
        return self.ldap_connection.write(*args, **kwargs)

    def run(self):
        self.connect()
        
        logging.info("Find target object: %s" % self.object.get("distinguishedName"))
        logging.info("New owner will be: %s" % self.owner.get("distinguishedName"))
        self.security_descriptor["OwnerSid"] = LDAP_SID(self.owner.get_raw("objectSid"))
        ret = self.write(self.object.get("distinguishedName"),  {'nTSecurityDescriptor':[ldap3.MODIFY_REPLACE, [self.security_descriptor.getData()]]})

        if ret['result'] == 0:
            logging.info("Object Owner modified successfully !")
        else :
            if ret['result'] == 50:
                raise Exception('Could not modify object, the server reports insufficient rights: %s', ret['message'])
            elif ret['result'] == 19:
                raise Exception('Could not modify object, the server reports a constrained violation: %s', ret['message'])
            else:
                raise Exception('The server returned an error: %s', ret['message'])

        # self.write()


    @property
    def domain(self) -> str:
        if self._domain is not None:
            return self._domain

        domains = self.search(
            "(&(objectClass=domain)(distinguishedName=%s))"
            % self.ldap_connection.root_name_path,
            attributes=["name","objectSid"],
        )
        if len(domains) == 0:
            logging.debug(
                    "Could not find domain root domain %s, trying default %s" 
                    % (self.ldap_connection.root_name_path, self.ldap_connection.default_path)
                    )

            domains = self.search(
                "(&(objectClass=domain)(distinguishedName=%s))"
                % self.ldap_connection.default_path,
                attributes=["name","objectSid"],
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
    def object(self) -> LDAPEntry:
        if self._object is not None:
            return self._object

        object_sid = self.options.target_sid

        objects = self.search(
            "(objectSid=%s)" % object_sid,
            attributes=["distinguishedName", "nTSecurityDescriptor", "primaryGroupId"]
        )

        if len(objects) == 0:
            raise Exception("Could not find object with Sid: %s" % object_sid)

        self._object = objects[0]

        return self._object

    @property
    def owner(self) -> LDAPEntry:
        if self._owner is not None:
            return self._owner
        
        if self.options.owner_sid is not None:
            owner = self.search(
                "(objectSid=%s)" % self.options.owner_sid,
                attributes=["distinguishedName", "objectSid"]
            )
            if len(owner) == 0:
                raise Exception("Could not find owner")
        else:
            owner = self.search(
                "(sAMAccountName=%s)"
                % self.target.username,
                attributes=["distinguishedName","objectSid"],
            )
        self._owner = owner[0]
        return self._owner

    
    @property
    def security_descriptor(self) -> SR_SECURITY_DESCRIPTOR:
        if self._security_descriptor is not None:
            return self._security_descriptor

        self._security_descriptor = SR_SECURITY_DESCRIPTOR()
        self._security_descriptor.fromString(self.object.get_raw("nTSecurityDescriptor"))

        return self.security_descriptor

def set_objectowner(options: argparse.Namespace):
    g = SetObjectOwner(options)
    g.run()