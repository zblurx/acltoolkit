import logging
from typing import Any
from enum import IntFlag
import ldap3
from binascii import unhexlify
import ssl
import os
from impacket.ldap import ldap
from ldap3.protocol.microsoft import security_descriptor_control
from impacket.ldap.ldapasn1 import Control

from acltoolkit.target import Target



class SecurityInformation(IntFlag):
    OWNER_SECURITY_INFORMATION = 0x01
    GROUP_SECURITY_INFORMATION = 0x02
    DACL_SECURITY_INFORMATION = 0x04
    SACL_SECURITY_INFORMATION = 0x08
    UNPROTECTED_SACL_SECURITY_INFORMATION = 0x10000000
    UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000


DEFAULT_CONTROL_FLAGS: 'list["Control"]' = [
    ldap.SimplePagedResultsControl(size=50),
]

class LDAPEntry:
    def __init__(self, search_entry):
        attributes = dict()
        for attr, value in search_entry["raw_attributes"].items():
            if len(value) == 0:
                continue
            vals = (
                list(map(lambda x: bytes(x), value))
                if len(value) > 1
                else bytes(value[0])
            )
            attributes[str(attr)] = vals
        self.attributes = attributes

    def get(self, key: str) -> str:
        value = self.get_raw(key)
        return value.decode() if value else None

    def get_raw(self, key: str) -> Any:
        if key not in self.attributes:
            return None
        return self.attributes[key]

    def __repr__(self) -> str:
        return "<LDAPEntry (%s)>" % repr(self.attributes)

class LDAPConnection:
    def __init__(self, scheme: str, target: Target):
        self.target = target
        self._root_name_path = None
        self._default_path = None
        self.scheme = scheme
        self._ldap_server = None
        self.ldap_session = None

    def connect(self):
        if self.scheme == "ldaps":
            try:
                return self.init_session(ssl.PROTOCOL_TLSv1_2)
            except ldap3.core.exceptions.LDAPSocketOpenError:
                return self.init_session(ssl.PROTOCOL_TLSv1)
        else:
            return self.init_session(None)

    def init_session(self, ssl_version):
        target = self.target

        if self.scheme == "ldaps":
            use_ssl = True
            port = 636
            tls = ldap3.Tls(validate=ssl.CERT_NONE, version= ssl_version)
        else:
            use_ssl = False
            port = 389
            tls = None

        logging.debug("Connecting to LDAP at %s (%s)" % (repr(target.remote_name), target.dc_ip))

        self.ldap_server = ldap3.Server(self.target.dc_ip, get_info=ldap3.ALL, port=port, use_ssl=use_ssl, tls=tls)

        try:
            if self.target.do_kerberos:
                self.ldap_session = ldap3.Connection(self.ldap_server)
                self.ldap_session.bind()
                self.kerberosLogin(
                    connection = self.ldap_session, 
                    user=target.username,
                    password=target.password,
                    domain=target.domain,
                    lmhash=target.lmhash,
                    nthash=target.nthash,
                    remote_name=target.remote_name,
                    kdcHost=target.dc_ip,
                    )
            else:
                if target.nthash != '':
                    self.ldap_session = ldap3.Connection(
                            server=self.ldap_server,
                            user="%s\%s" % (target.domain, target.username),
                            password=target.ntlmhash,
                            authentication=ldap3.NTLM,
                            auto_bind=True
                    )
                else:
                    self.ldap_session = ldap3.Connection(
                            server=self.ldap_server,
                            user="%s\%s" % (target.domain, target.username),
                            password=target.password,
                            authentication=ldap3.NTLM,
                            auto_bind=True
                    )

        except ldap3.core.exceptions.LDAPUnknownAuthenticationMethodError as e:
            if "invalidCredentials" in str(e):
                error_text = "Invalid credentials"
            else:
                error_text = str(e)
            logging.warning("Got error while connecting to LDAP: %s" % error_text)
            exit(1)

        logging.debug(
            "Connected to %s, port %d, SSL %s"
            % (target.dc_ip, self.ldap_server.port, self.ldap_server.ssl)
        )

        return self.ldap_session
    
    def search(
        self,
        search_filter: str,
        controls = security_descriptor_control(
                sdflags=(
                    (
                        SecurityInformation.OWNER_SECURITY_INFORMATION
                        | SecurityInformation.GROUP_SECURITY_INFORMATION
                        | SecurityInformation.DACL_SECURITY_INFORMATION
                        | SecurityInformation.UNPROTECTED_DACL_SECURITY_INFORMATION
                    ).value
                )
            ),
        search_base: str = None,
        *args,
        **kwargs
    ) -> 'list["LDAPEntry"]':
        if search_base is None:
            search_base = self.default_path

        self.ldap_session.search(
            search_filter=search_filter,
            search_base=search_base,
            controls=controls,
            *args,
            **kwargs
        )

        results = self.ldap_session.response
        entries: list["LDAPEntry"] = list(
            map(
                lambda entry: LDAPEntry(entry),
                filter(
                    lambda entry: "raw_attributes" in entry, results),
            )
        )
        return entries

    def write(
        self,
        target_dn: str,
        changes: dict,
        controls = security_descriptor_control(
                sdflags=(
                    (
                        SecurityInformation.OWNER_SECURITY_INFORMATION
                        | SecurityInformation.GROUP_SECURITY_INFORMATION
                        | SecurityInformation.DACL_SECURITY_INFORMATION
                        | SecurityInformation.UNPROTECTED_DACL_SECURITY_INFORMATION
                    ).value
                )
            ),
        ):
        self.ldap_session.modify(dn=target_dn, changes=changes,controls=controls)
        return self.ldap_session.result
    
    def _set_root_dse(self) -> None:
        dses = self.search(
            "(objectClass=*)",
            search_base="",
            attributes=[
                "*"
            ],
            search_scope=ldap3.BASE,
        )
        assert len(dses) == 1

        dse = dses[0]
        self._root_name_path = dse.get("rootDomainNamingContext")
        self._default_path = dse.get("defaultNamingContext")
        self._configuration_path = dse.get("configurationNamingContext")

    def kerberosLogin(self, connection, user, password, domain='', lmhash='', nthash='', aesKey='', remote_name='', kdcHost=None, TGT=None,
                      TGS=None, useCache=True):
        """
        logins into the target system explicitly using Kerberos. Hashes are used if RC4_HMAC is supported.
        :param string user: username
        :param string password: password for the user
        :param string domain: domain where the account is valid for (required)
        :param string lmhash: LMHASH used to authenticate using hashes (password is not used)
        :param string nthash: NTHASH used to authenticate using hashes (password is not used)
        :param string aesKey: aes256-cts-hmac-sha1-96 or aes128-cts-hmac-sha1-96 used for Kerberos authentication
        :param string kdcHost: hostname or IP Address for the KDC. If None, the domain will be used (it needs to resolve tho)
        :param struct TGT: If there's a TGT available, send the structure here and it will be used
        :param struct TGS: same for TGS. See smb3.py for the format
        :param bool useCache: whether or not we should use the ccache for credentials lookup. If TGT or TGS are specified this is False
        :return: True, raises a LDAPSessionError if error.
        """

        if lmhash != '' or nthash != '':
            if len(lmhash) % 2:
                lmhash = '0' + lmhash
            if len(nthash) % 2:
                nthash = '0' + nthash
            try:  # just in case they were converted already
                lmhash = unhexlify(lmhash)
                nthash = unhexlify(nthash)
            except TypeError:
                pass

        # Importing down here so pyasn1 is not required if kerberos is not used.
        from pyasn1.codec.ber import encoder, decoder
        from pyasn1.type.univ import noValue
        from impacket.krb5.ccache import CCache
        from impacket.krb5.asn1 import AP_REQ, Authenticator, TGS_REP, seq_set
        from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
        from impacket.krb5 import constants
        from impacket.krb5.types import Principal, KerberosTime, Ticket
        from impacket.spnego import TypesMech, SPNEGO_NegTokenInit
        import datetime

        if TGT is not None or TGS is not None:
            useCache = False

        if useCache:
            try:
                ccache = CCache.loadFile(os.getenv('KRB5CCNAME'))
            except Exception as e:
                # No cache present
                print(e)
                pass
            else:
                # retrieve domain information from CCache file if needed
                if domain == '':
                    domain = ccache.principal.realm['data'].decode('utf-8')
                    logging.debug('Domain retrieved from CCache: %s' % domain)

                logging.debug('Using Kerberos Cache: %s' % os.getenv('KRB5CCNAME'))
                principal = 'ldap/%s@%s' % (self.target.remote_name.upper(), domain.upper())
                creds = ccache.getCredential(principal)
                if creds is None:
                    # Let's try for the TGT and go from there
                    principal = 'krbtgt/%s@%s' % (domain.upper(), domain.upper())
                    creds = ccache.getCredential(principal)
                    if creds is not None:
                        TGT = creds.toTGT()
                        logging.debug('Using TGT from cache')
                    else:
                        logging.debug('No valid credentials found in cache')
                else:
                    TGS = creds.toTGS(principal)
                    logging.debug('Using TGS from cache')

                # retrieve user information from CCache file if needed
                if user == '' and creds is not None:
                    user = creds['client'].prettyPrint().split(b'@')[0].decode('utf-8')
                    logging.debug('Username retrieved from CCache: %s' % user)
                elif user == '' and len(ccache.principal.components) > 0:
                    user = ccache.principal.components[0]['data'].decode('utf-8')
                    logging.debug('Username retrieved from CCache: %s' % user)

        # First of all, we need to get a TGT for the user
        userName = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        if TGT is None:
            if TGS is None:
                tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, password, domain, lmhash, nthash,
                                                                        aesKey, kdcHost)
        else:
            tgt = TGT['KDC_REP']
            cipher = TGT['cipher']
            sessionKey = TGT['sessionKey']

        if TGS is None:
            
            serverName = Principal('ldap/%s' % remote_name, type=constants.PrincipalNameType.NT_SRV_INST.value)
            tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(serverName, domain, kdcHost, tgt, cipher,
                                                                    sessionKey)
        else:
            tgs = TGS['KDC_REP']
            cipher = TGS['cipher']
            sessionKey = TGS['sessionKey']

            # Let's build a NegTokenInit with a Kerberos REQ_AP

        blob = SPNEGO_NegTokenInit()

        # Kerberos
        blob['MechTypes'] = [TypesMech['MS KRB5 - Microsoft Kerberos 5']]

        # Let's extract the ticket from the TGS
        tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
        ticket = Ticket()
        ticket.from_asn1(tgs['ticket'])

        # Now let's build the AP_REQ
        apReq = AP_REQ()
        apReq['pvno'] = 5
        apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

        opts = []
        apReq['ap-options'] = constants.encodeFlags(opts)
        seq_set(apReq, 'ticket', ticket.to_asn1)

        authenticator = Authenticator()
        authenticator['authenticator-vno'] = 5
        authenticator['crealm'] = domain
        seq_set(authenticator, 'cname', userName.components_to_asn1)
        now = datetime.datetime.utcnow()

        authenticator['cusec'] = now.microsecond
        authenticator['ctime'] = KerberosTime.to_asn1(now)

        encodedAuthenticator = encoder.encode(authenticator)

        # Key Usage 11
        # AP-REQ Authenticator (includes application authenticator
        # subkey), encrypted with the application session key
        # (Section 5.5.1)
        encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 11, encodedAuthenticator, None)

        apReq['authenticator'] = noValue
        apReq['authenticator']['etype'] = cipher.enctype
        apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

        blob['MechToken'] = encoder.encode(apReq)

        request = ldap3.operation.bind.bind_operation(connection.version, ldap3.SASL, user, None, 'GSS-SPNEGO',
                                                  blob.getData())

        # Done with the Kerberos saga, now let's get into LDAP
        if connection.closed:  # try to open connection if closed
            connection.open(read_server_info=False)

        connection.sasl_in_progress = True
        response = connection.post_send_single_response(connection.send('bindRequest', request, None))
        connection.sasl_in_progress = False
        if response[0]['result'] != 0:
            raise Exception(response)

        connection.bound = True

        return True

    @property
    def root_name_path(self) -> str:
        if self._root_name_path is not None:
            return self._root_name_path

        self._set_root_dse()

        return self._root_name_path

    @property
    def default_path(self) -> str:
        if self._default_path is not None:
            return self._default_path

        self._set_root_dse()

        return self._default_path

    @property
    def configuration_path(self) -> str:
        if self._configuration_path is not None:
            return self._configuration_path

        self._set_root_dse()

        return self._configuration_path
