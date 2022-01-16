# acltoolkit

ACL Toolkit is an ACL abuse swiss-knife.

## Installation

```bash
pip install .
```

ou

```bash
python3 -m pipx pip install .
```

## Usage

```bash
$ acltoolkit -h
usage: acltoolkit [-h] [-debug] [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-dc-ip ip address] [-scheme ldap scheme] target {get-objectacl,set-objectowner,give-genericall} ...

ACL abuse swiss-knife

positional arguments:
  target                [[domain/]username[:password]@]<target name or address>
  {get-objectacl,set-objectowner,give-genericall}
                        Action
    get-objectacl       Get Object ACL
    set-objectowner     Modify Object Owner
    give-genericall     Grant an object GENERIC ALL on a targeted object

optional arguments:
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