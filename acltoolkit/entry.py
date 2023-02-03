import argparse
import logging

from impacket.examples import logger

from acltoolkit.get_objectacl import get_objectacl
from acltoolkit.set_logon_script import set_logonscript
from acltoolkit.set_objectowner import set_objectowner
from acltoolkit.give_genericall import give_genericall
from acltoolkit.give_dcsync import give_dcsync
from acltoolkit.add_groupmember import add_groupmember

def main():
    logger.init()

    parser = argparse.ArgumentParser(
        description="ACL abuse swiss-army knife", add_help=True
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

    parser.add_argument(
        "-scheme",
        action="store",
        metavar="ldap scheme",
        choices=["ldap", "ldaps"],
        default="ldaps",
    )

    subparsers = parser.add_subparsers(help="Action", dest="action", required=True)

    get_objectacl_parser = subparsers.add_parser("get-objectacl", help="Get Object ACL")

    get_objectacl_parser.add_argument(
        "-object",
        action="store",
        metavar="object",
        help=(
            "Dump ACL for <object>. Parameter can be a sAMAccountName, a name, a DN or an objectSid"
        ),
    )

    get_objectacl_parser.add_argument(
        "-all",
        action="store_true",
        help=(
            "List every ACE of the object, even the less-interesting ones"
        ),
    )

    set_objectowner_parser = subparsers.add_parser("set-objectowner", help="Modify Object Owner")

    set_objectowner_parser.add_argument(
        "-target-sid",
        action="store",
        metavar="target_sid",
        help=(
            "Object Sid targeted"
        ),
        required=True
    )

    set_objectowner_parser.add_argument(
        "-owner-sid",
        action="store",
        metavar="owner_sid",
        help=(
            "New Owner Sid"
        )
    )

    give_genericall_parser = subparsers.add_parser("give-genericall", help="Grant an object GENERIC ALL on a targeted object")

    give_genericall_parser.add_argument(
        "-target-sid",
        action="store",
        metavar="target_sid",
        help=(
            "Object Sid targeted"
        ),
        required=True
    )

    give_genericall_parser.add_argument(
        "-granted-sid",
        action="store",
        metavar="owner_sid",
        help=(
            "Object Sid granted GENERIC_ALL"
        )
    )

    give_dcsync_parser = subparsers.add_parser("give-dcsync", help="Grant an object DCSync capabilities on the domain")

    give_dcsync_parser.add_argument(
        "-granted-sid",
        action="store",
        metavar="owner_sid",
        help=(
            "Object Sid granted DCSync capabilities"
        )
    )

    add_groupmember_parser = subparsers.add_parser("add-groupmember", help="Add Member to Group")

    add_groupmember_parser.add_argument(
        "-user",
        action="store",
        metavar="user",
        help=(
            "User added to a group"
        ),
    )

    add_groupmember_parser.add_argument(
        "-group",
        action="store",
        metavar="group",
        help=(
            "Group where the user will be added"
        ),
        required=True
    )

    set_logonscript_parser = subparsers.add_parser("set-logonscript", help="Change Logon Sript of User")

    set_logonscript_parser.add_argument(
        "-target-sid",
        action="store",
        metavar="target_sid",
        help=(
            "Object Sid of targeted user"
        ),
        required=True
    )

    set_logonscript_parser.add_argument(
        "-script-path",
        action="store",
        metavar="script_path",
        help=(
            "Script path to set for the targeted user"
        ),
        required=True
    )

    set_logonscript_parser.add_argument(
        "-logonscript-type",
        action="store",
        metavar="logonscript_type",
        help=(
            "Logon Script variable to change (default is scriptPath)"
        ),
        choices=['scriptPath', 'msTSInitialProgram']
    )

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    if options.action == "get-objectacl":
        get_objectacl(options)
    elif options.action == "set-objectowner":
        set_objectowner(options)
    elif options.action == "give-genericall":
        give_genericall(options)
    elif options.action == "give-dcsync":
        give_dcsync(options)
    elif options.action == "add-groupmember":
        add_groupmember(options)
    elif options.action == "set-logonscript":
        set_logonscript(options)
    else:
        raise Exception("Action not implemented: %s" % options.action)

if __name__ == "__main__":
    main()