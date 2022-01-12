import argparse
import logging

from impacket.examples import logger

from acltlk.get import get

def main():
    logger.init()

    parser = argparse.ArgumentParser(
        description="ACL Management tool", add_help=True
    )

    parser.add_argument(
        "target",
        action="store",
        help="[[domain/]username[:password]@]<target name or address>",
    )

    parser.add_argument("-debug", action="store_true", help="Turn DEBUG output ON")

    group = parser.add_argument_group("authentication")
    group.add_argument(
        "-hashes",
        action="store",
        metavar="LMHASH:NTHASH",
        help="NTLM hashes, format is LMHASH:NTHASH",
    )
    parser.add_argument(
        "-no-pass", action="store_true", help="don't ask for password (useful for -k)"
    )
    parser.add_argument(
        "-k",
        action="store_true",
        help="Use Kerberos authentication. Grabs credentials from ccache file "
        "(KRB5CCNAME) based on target parameters. If valid credentials "
        "cannot be found, it will use the ones specified in the command "
        "line",
    )
    parser.add_argument(
        "-dc-ip",
        action="store",
        metavar="ip address",
        help=(
            "IP Address of the domain controller. If omitted it will use the domain "
            "part (FQDN) specified in the target parameter"
        ),
    )

    subparsers = parser.add_subparsers(help="Action", dest="action", required=True)

    get_parser = subparsers.add_parser("get", help="Get Object ACL")

    get_parser.add_argument(
        "-user",
        action="store",
        metavar="user",
        help=(
            "Dump ACL for <user>"
        ),
    )

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    if options.action == "get":
        get(options)
    else:
        raise NotExistingActionError("Action not implemented: %s" % options.action)

if __name__ == "__main__":
    main()