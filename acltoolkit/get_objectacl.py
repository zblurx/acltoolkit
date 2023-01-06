import argparse
import logging

from ldap3.protocol.formatters.formatters import format_sid, format_uuid_le
from ldap3.protocol.microsoft import security_descriptor_control
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR

from acltoolkit.ldap import LDAPConnection, LDAPEntry, SecurityInformation, DEFAULT_CONTROL_FLAGS
from acltoolkit.target import Target
from acltoolkit.formatting import pretty_print
from acltoolkit.constants import ACTIVE_DIRECTORY_RIGHTS, WELL_KNOWN_SIDS, EXTENDED_RIGHTS_MAP, JUICY_ADRIGHTS

class GetObjectAcl:
    def __init__(self, options: argparse.Namespace):
        self.options = options

        self.target = Target(options)
        self._domain = None
        self._object = None
        self._primary_group = None
        self._sids = None
        self._groups = None
        self._sid_map = {}
        self._members = None

        self.ldap_connection = None

        self._security_descriptor = None

    def connect(self):
        self.ldap_connection = LDAPConnection(self.options.scheme, self.target)
        self.ldap_connection.connect()

    def search(self, *args, **kwargs) -> 'list["LDAPEntry"]':
        return self.ldap_connection.search(*args, **kwargs)

    def run(self):
        self.connect()

        object_info = dict()
        object_info["Sid"] = format_sid(self.object.get_raw("objectSid"))
        object_info["Name"] = self.sid_lookup(object_info["Sid"])
        object_info["DN"] = self.object.get("distinguishedName")
        object_info["Class"] = [i.decode() for i in self.object.get_raw("objectClass")]
        
        if b'group' in self.object.get_raw("objectClass"):
            members = list()
            for member in self.members:
                member_output = dict()
                member_output['Sid'] = format_sid(member.get_raw("objectSid"))
                member_output['Name'] = member.get('name')
                member_output['DN'] = member.get('distinguishedName')

                members.append(member_output)
            object_info["Members"] = members
        
        if b'user' in self.object.get_raw("objectClass"):
            object_info["adminCount"] = True if self.object.get("adminCount") else False
            
            logon_script = dict()
            logon_script["scriptPath"] = self.object.get_raw("scriptPath")
            logon_script["msTSInitialProgram"] = self.object.get_raw("msTSInitialProgram")
            
            object_info["Logon Script"] = logon_script

            primary_group_info = dict()
            primary_group_info["Sid"] = format_sid(self.primary_group.get_raw("objectSid"))
            primary_group_info["Name"] = self.sid_lookup(primary_group_info["Sid"])
            primary_group_info["DN"] = self.primary_group.get("distinguishedName")
        
            object_info["PrimaryGroup"] = primary_group_info

        groups = list()

        for group in self.groups:
            group_output = dict()
            group_output["Sid"] = format_sid(group.get_raw("objectSid"))
            group_output["Name"] = self.sid_lookup(group_output["Sid"])
            group_output["DN"] = group.get("distinguishedName")

            groups.append(group_output)

        object_info["Groups"] = groups

        owner_info = dict()
        owner_info["Sid"] = self.security_descriptor["OwnerSid"].formatCanonical()
        owner_info["Name"] = self.sid_lookup(owner_info["Sid"])

        object_info["Owner"] = owner_info

        ownergroup_info = dict()
        ownergroup_info["Sid"] = self.security_descriptor["GroupSid"].formatCanonical()
        ownergroup_info["Name"] = self.sid_lookup(ownergroup_info["Sid"])

        object_info["OwnerGroup"] = ownergroup_info

        dacl = list()
        for ace in self.security_descriptor['Dacl'].aces:
            ace_output = dict()
            ace_output['ObjectSid'] = ace['Ace']['Sid'].formatCanonical()
            ace_output['Name'] = self.sid_lookup(ace['Ace']['Sid'].formatCanonical())
            ace_output['AceType'] = ace['TypeName']
            ace_output['AccessMask'] = ace['Ace']['Mask']['Mask']
            ace_output['ADRights'] = self.ace_access_mask_lookup(ace['Ace']['Mask']['Mask'])
            ace_output['IsInherited'] = bool(ace['AceFlags'] & 0x10)
            try:
                ace_output['ObjectAceType'] = format_uuid_le(ace['Ace']['ObjectType']) if ace['Ace']['ObjectType'] else '{00000000-0000-0000-0000-000000000000}'
                ace_output['ObjectAceType'] = EXTENDED_RIGHTS_MAP[ace_output['ObjectAceType']]
                ace_output['InheritedObjectType'] = format_uuid_le(ace['Ace']['InheritedObjectType'])
            except KeyError:
                pass
            if self.options.all or any(juicy_adright in ace_output['ADRights'] for juicy_adright in JUICY_ADRIGHTS):
                dacl.append(ace_output)

        if len(dacl) > 0:
            # Is this even possible ?!
            object_info['Dacl'] = dacl

        pretty_print(object_info)

    def ace_access_mask_lookup(self, value) -> list :
        try:
            int_value = int(value)
        except ValueError:
            return value
        
        adrights = list()
        for flag, flag_item in ACTIVE_DIRECTORY_RIGHTS.items():
            if (int_value & flag) == flag:
                adrights.append(flag_item)
                int_value ^= flag

        return adrights

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

        self._sid_map[sid] = '%s\%s' % (self.domain.get("name"),result.get("name"))
        return self._sid_map[sid]
    
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

        if self.options.object is not None:
            objectname = self.options.object
        else:
            objectname = self.target.username
        
        objects = self.search(
            "(|(sAMAccountName=%(o)s)(name=%(o)s)(objectSid=%(o)s)(distinguishedName=%(o)s))" % {'o': objectname} ,
            attributes=["objectSid", "distinguishedName", "nTSecurityDescriptor", "primaryGroupId", "member", "objectClass", "adminCount", "scriptPath", "msTSInitialProgram"],
        )

        if len(objects) == 0:
            raise Exception("Could not find such object: %s" % objectname)

        self._object = objects[0]

        return self._object

    @property
    def members(self) -> 'list["LDAPEntry"]':
        if self._members is not None:
            return self._members
        self._members = self.search("(|(memberOf=%s)(primaryGroupID=%s))" % (self.object.get("distinguishedName"), format_sid(self.object.get_raw("objectSid")).split('-')[-1]),
            attributes=["objectSid","name","distinguishedName"])
        return self._members

    @property
    def groups(self) -> 'list["LDAPEntry"]':
        if self._groups is not None:
            return self._groups
        self._groups = self.search(
            "(member:1.2.840.113556.1.4.1941:=%s)" % self.object.get("distinguishedName"),
            attributes=["objectSid","name","distinguishedName"],
        )
        return self._groups

    @property
    def primary_group(self) -> 'list["LDAPEntry"]':
        if self._primary_group is not None:
            return self._primary_group

        primary_group = self.search('(objectSid=%s-%s)' % (format_sid(self.domain.get_raw("objectSid")), self.object.get("primaryGroupID")), attributes=["objectSid","name", "distinguishedName"])  
        self._primary_group = primary_group[0]

        return self._primary_group

    @property
    def user_sids(self) -> 'list[str]':
        """List of effective SIDs for user"""
        if self._user_sids is not None:
            return self._user_sids

        self._user_sids = list(
            map(
                lambda entry: format_sid(entry.get_raw("objectSid")),
                [*self.groups, self.object],
            )
        )

        return self._user_sids

    @property
    def security_descriptor(self) -> SR_SECURITY_DESCRIPTOR:
        if self._security_descriptor is not None:
            return self._security_descriptor

        self._security_descriptor = SR_SECURITY_DESCRIPTOR()
        self._security_descriptor.fromString(self.object.get_raw("nTSecurityDescriptor"))

        return self.security_descriptor

def get_objectacl(options: argparse.Namespace):
    g = GetObjectAcl(options)
    g.run()