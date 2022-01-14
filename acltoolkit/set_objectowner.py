import argparse
import logging

from ldap3.protocol.microsoft import security_descriptor_control
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR

from acltoolkit.ldap import LDAPConnection, LDAPEntry, SecurityInformation, DEFAULT_CONTROL_FLAGS
from acltoolkit.target import Target
from acltoolkit.constants import WELL_KNOWN_SIDS

class SetObjectOwner:
    def __init__(self, options: argparse.Namespace):
        self.options = options

        self.target = Target(options)
        self._domain = None
        self._object = None
        self._user_sids = None
        self._sid_map = {}

        self.ldap_connection = None

        self._security_descriptor = None

    def connect(self):
        self.ldap_connection = LDAPConnection(self.options.scheme, self.target)
        self.ldap_connection.connect()

    def search(self, *args, **kwargs) -> 'list["LDAPEntry"]':
        return self.ldap_connection.search(*args, **kwargs)

    def run(self):
        self.connect()

        logging.info("Find target object: %s" % self.object.get("distinguishedName"))
        

    def sid_lookup(self, sid: str) -> str:
        if sid in WELL_KNOWN_SIDS:
            return WELL_KNOWN_SIDS[sid]
    
        results = self.search(
            "(&(objectSid=%s)(|(objectClass=group)(objectClass=user)))" % sid,
            attributes=["name", "objectSid"],
        )

        if len(results) == 0:
            return sid
        
        result = results[0]

        return '%s\%s' % (self.domain.get("name"),result.get("name"))

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

        if self.options.target_sid is not None:
            object_sid = self.options.target_sid
        else:
            object_sid = self.target.username

        controls = [
            *security_descriptor_control(
                sdflags=(
                    (
                        SecurityInformation.OWNER_SECURITY_INFORMATION
                        | SecurityInformation.GROUP_SECURITY_INFORMATION
                        | SecurityInformation.DACL_SECURITY_INFORMATION
                        | SecurityInformation.UNPROTECTED_DACL_SECURITY_INFORMATION
                    ).value
                )
            ),
            *DEFAULT_CONTROL_FLAGS,
        ]

        objects = self.search(
            "(objectSid=%s)" % object_sid,
            attributes=["distinguishedName", "nTSecurityDescriptor", "primaryGroupId"],
            controls=controls
        )

        if len(objects) == 0:
            raise Exception("Could not find object with Sid: %s" % object_sid)

        self._object = objects[0]

        return self._object
    
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