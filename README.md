# acltoolkit

`acltoolkit` is an ACL abuse swiss-army knife. It implements multiple ACL abuses. 

## Table of Contents

- [acltoolkit](#acltoolkit)
  - [Table of Contents](#table-of-contents)
  - [Installation](#installation)
  - [Usage](#usage)
  - [Commands](#commands)
    - [get-objectacl](#get-objectacl)
    - [set-objectowner](#set-objectowner)
    - [give-genericall](#give-genericall)
    - [give-dcsync](#give-dcsync)
    - [add-groupmember](#add-groupmember)
    - [set-logonscript](#set-logonscript)

## Installation

```bash
git clone https://github.com/zblurx/acltoolkit.git
cd acltoolkit
pip install .
```

or

```bash
git clone https://github.com/zblurx/acltoolkit.git
cd acltoolkit
python3 -m pipx pip install .
```

## Usage

```$ acltoolkit -h
usage: acltoolkit [-h] [-debug] [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-dc-ip ip address] [-scheme ldap scheme]
                  target {get-objectacl,set-objectowner,give-genericall,give-dcsync,add-groupmember,set-logonscript} ...

ACL abuse swiss-army knife

positional arguments:
  target                [[domain/]username[:password]@]<target name or address>
  {get-objectacl,set-objectowner,give-genericall,give-dcsync,add-groupmember,set-logonscript}
                        Action
    get-objectacl       Get Object ACL
    set-objectowner     Modify Object Owner
    give-genericall     Grant an object GENERIC ALL on a targeted object
    give-dcsync         Grant an object DCSync capabilities on the domain
    add-groupmember     Add Member to Group
    set-logonscript     Change Logon Sript of User

options:
  -h, --help            show this help message and exit
  -debug                Turn DEBUG output ON
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the
                        command line
  -dc-ip ip address     IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter
  -scheme ldap scheme

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
```

## Commands

### get-objectacl

```text
$ acltoolkit get-objectacl -h
usage: acltoolkit target get-objectacl [-h] [-object object] [-all]

options:
  -h, --help      show this help message and exit
  -object object  Dump ACL for <object>. Parameter can be a sAMAccountName, a name, a DN or an objectSid
  -all            List every ACE of the object, even the less-interesting ones
```

The `get-objectacl` will take a sAMAccountName, a name, a DN or an objectSid as input with `-object` and will list Sid, Name, DN, Class, adminCount, LogonScript configured, Primary Group, Owner and DACL of it. If no parameter supplied, will list informations about the account used to authenticate.

```text
$ acltoolkit waza.local/jsmith:Password#123@192.168.56.112 get-objectacl
Sid                 : S-1-5-21-267175082-2660600898-836655089-1103
Name                : waza\John Smith
DN                  : CN=John Smith,CN=Users,DC=waza,DC=local
Class               : top, person, organizationalPerson, user
adminCount          : False

Logon Script
  scriptPath        : \\WAZZAAAAAA\OCD\test.bat
  msTSInitialProgram: \\WAZZAAAAAA\OCD\test.bat

PrimaryGroup
  Sid               : S-1-5-21-267175082-2660600898-836655089-513
  Name              : waza\Domain Users
  DN                : CN=Domain Users,OU=Builtin Groups,DC=waza,DC=local

[...]

OwnerGroup
  Sid               : S-1-5-21-267175082-2660600898-836655089-512
  Name              : waza\Domain Admins

Dacl
  ObjectSid         : S-1-1-0
  Name              : Everyone
  AceType           : ACCESS_ALLOWED_OBJECT_ACE
  AccessMask        : 256
  ADRights          : EXTENDED_RIGHTS
  IsInherited       : False
  ObjectAceType     : User-Change-Password

[...]

  ObjectSid         : S-1-5-32-544
  Name              : BUILTIN\Administrator
  AceType           : ACCESS_ALLOWED_ACE
  AccessMask        : 983485
  ADRights          : WRITE_OWNER, WRITE_DACL, GENERIC_READ, DELETE, EXTENDED_RIGHTS, WRITE_PROPERTY, SELF, CREATE_CHILD
  IsInherited       : True
```

### set-objectowner

```text
$ acltoolkit set-objectowner -h
usage: acltoolkit target set-objectowner [-h] -target-sid target_sid [-owner-sid owner_sid]

options:
  -h, --help            show this help message and exit
  -target-sid target_sid
                        Object Sid targeted
  -owner-sid owner_sid  New Owner Sid
```

The `set-objectowner` will take as input a target sid and an owner sid, and will change the owner of the target object.

### give-genericall

```text
$ acltoolkit give-genericall -h
usage: acltoolkit target give-genericall [-h] -target-sid target_sid [-granted-sid owner_sid]

options:
  -h, --help            show this help message and exit
  -target-sid target_sid
                        Object Sid targeted
  -granted-sid owner_sid
                        Object Sid granted GENERIC_ALL
```

The `give-genericall` will take as input a target sid and a granted sid, and will change give GENERIC_ALL DACL to the granted SID to the target object.

### give-dcsync

```text
$ acltoolkit give-dcsync -h
usage: acltoolkit target give-dcsync [-h] [-granted-sid owner_sid]

options:
  -h, --help            show this help message and exit
  -granted-sid owner_sid
                        Object Sid granted DCSync capabilities
```

The `give-dcsync` will take as input a granted sid, and will change give DCSync capabilities to the granted SID.

### add-groupmember

```text
$ acltoolkit add-groupmember -h
usage: acltoolkit target add-groupmember [-h] [-user user] -group group

options:
  -h, --help    show this help message and exit
  -user user    User added to a group
  -group group  Group where the user will be added
```

The `add-groupmember` will take as input a user sAMAccountName and a group sAMAccountName, and will add the user to the group

### set-logonscript

```text
$ acltoolkit set-logonscript -h
usage: acltoolkit target set-logonscript [-h] -target-sid target_sid -script-path script_path [-logonscript-type logonscript_type]

options:
  -h, --help            show this help message and exit
  -target-sid target_sid
                        Object Sid of targeted user
  -script-path script_path
                        Script path to set for the targeted user
  -logonscript-type logonscript_type
                        Logon Script variable to change (default is scriptPath)
```

The `set-logonscript` will take as input a target sid and a script path, and will the the Logon Script path of the targeted user to the script path specified.