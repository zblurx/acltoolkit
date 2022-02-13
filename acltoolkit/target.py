from impacket.examples.utils import parse_target

class Target:
    def __init__(self, options):
        domain, username, password, remote_name = parse_target(options.target)

        if domain is None:
            domain = ""

        if (
            password == ""
            and username != ""
            and options.hashes is None
            and options.no_pass is not True
        ):
            from getpass import getpass

            password = getpass("Password:")
        hashes = options.hashes
        if hashes is not None:
            hashes = hashes.split(':')
            if len(hashes) == 1:
                (nthash,) = hashes
                lmhash = nthash
            else:
                lmhash, nthash = hashes
        else:
            lmhash = nthash = ''
        
        if options.dc_ip is None:
            options.dc_ip = remote_name

        self.domain = domain
        self.username = username[:20]
        self.password = password
        self.remote_name = remote_name
        self.lmhash = lmhash
        self.nthash = nthash
        self.ntlmhash = "%s:%s" % (lmhash,nthash)
        self.do_kerberos = options.k
        self.dc_ip = options.dc_ip

        def __repr__(self) -> str:
            return "<Target (%s)>" % repr(self.__dict__)