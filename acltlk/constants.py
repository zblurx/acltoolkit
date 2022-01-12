

from enum import IntFlag
# https://docs.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.accesscontroltype?view=net-5.0
class ACCESS_CONTROL_TYPE(IntFlag):
    ALLOW = 0
    DENY = 1

# https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=net-5.0
class ACTIVE_DIRECTORY_RIGHTS(IntFlag):
    ACCESS_SYSTEM_SECURITY = 16777216
    SYNCHRONIZE = 1048576
    GENERIC_ALL = 983551
    WRITE_OWNER = 524288
    WRITE_DACL = 262144
    GENERIC_READ = 131220
    GENERIC_WRITE = 131112
    GENERIC_EXECUTE = 131076
    READ_CONTROL = 131072
    DELETE = 65536
    EXTENDED_RIGHT = 256
    LIST_OBJECT = 128
    DELETE_TREE = 64
    WRITE_PROPERTY = 32
    READ_PROPERTY = 16
    SELF = 8
    LIST_CHILDREN = 4
    DELETE_CHILD = 2
    CREATE_CHILD = 1

# Retrieved from Windows 2022 server via LDAP (CN=Extended-Rights,CN=Configuration,DC=...)
EXTENDED_RIGHTS_MAP = {
    "ab721a52-1e2f-11d0-9819-00aa0040529b": "Domain-Administer-Serve",
    "ab721a53-1e2f-11d0-9819-00aa0040529b": "User-Change-Password",
    "00299570-246d-11d0-a768-00aa006e0529": "User-Force-Change-Password",
    "ab721a54-1e2f-11d0-9819-00aa0040529b": "Send-As",
    "ab721a56-1e2f-11d0-9819-00aa0040529b": "Receive-As",
    "ab721a55-1e2f-11d0-9819-00aa0040529b": "Send-To",
    "c7407360-20bf-11d0-a768-00aa006e0529": "Domain-Password",
    "59ba2f42-79a2-11d0-9020-00c04fc2d3cf": "General-Information",
    "4c164200-20c0-11d0-a768-00aa006e0529": "User-Account-Restrictions",
    "5f202010-79a5-11d0-9020-00c04fc2d4cf": "User-Logon",
    "bc0ac240-79a9-11d0-9020-00c04fc2d4cf": "Membership",
    "a1990816-4298-11d1-ade2-00c04fd8d5cd": "Open-Address-Book",
    "77b5b886-944a-11d1-aebd-0000f80367c1": "Personal-Information",
    "e45795b2-9455-11d1-aebd-0000f80367c1": "Email-Information",
    "e45795b3-9455-11d1-aebd-0000f80367c1": "Web-Information",
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Synchronize",
    "1131f6ac-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Manage-Topology",
    "e12b56b6-0a95-11d1-adbb-00c04fd8d5cd": "Change-Schema-Maste",
    "d58d5f36-0a98-11d1-adbb-00c04fd8d5cd": "Change-Rid-Maste",
    "fec364e0-0a98-11d1-adbb-00c04fd8d5cd": "Do-Garbage-Collection",
    "0bc1554e-0a99-11d1-adbb-00c04fd8d5cd": "Recalculate-Hierarchy",
    "1abd7cf8-0a99-11d1-adbb-00c04fd8d5cd": "Allocate-Rids",
    "bae50096-4752-11d1-9052-00c04fc2d4cf": "Change-PDC",
    "440820ad-65b4-11d1-a3da-0000f875ae0d": "Add-GUID",
    "014bf69c-7b3b-11d1-85f6-08002be74fab": "Change-Domain-Maste",
    "e48d0154-bcf8-11d1-8702-00c04fb96050": "Public-Information",
    "4b6e08c0-df3c-11d1-9c86-006008764d0e": "msmq-Receive-Dead-Lette",
    "4b6e08c1-df3c-11d1-9c86-006008764d0e": "msmq-Peek-Dead-Lette",
    "4b6e08c2-df3c-11d1-9c86-006008764d0e": "msmq-Receive-computer-Journal",
    "4b6e08c3-df3c-11d1-9c86-006008764d0e": "msmq-Peek-computer-Journal",
    "06bd3200-df3e-11d1-9c86-006008764d0e": "msmq-Receive",
    "06bd3201-df3e-11d1-9c86-006008764d0e": "msmq-Peek",
    "06bd3202-df3e-11d1-9c86-006008764d0e": "msmq-Send",
    "06bd3203-df3e-11d1-9c86-006008764d0e": "msmq-Receive-journal",
    "b4e60130-df3f-11d1-9c86-006008764d0e": "msmq-Open-Connecto",
    "edacfd8f-ffb3-11d1-b41d-00a0c968f939": "Apply-Group-Policy",
    "037088f8-0ae1-11d2-b422-00a0c968f939": "RAS-Information",
    "9923a32a-3607-11d2-b9be-0000f87a36b2": "DS-Install-Replica",
    "cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd": "Change-Infrastructure-Maste",
    "be2bb760-7f46-11d2-b9ad-00c04f79f805": "Update-Schema-Cache",
    "62dd28a8-7f46-11d2-b9ad-00c04f79f805": "Recalculate-Security-Inheritance",
    "69ae6200-7f46-11d2-b9ad-00c04f79f805": "DS-Check-Stale-Phantoms",
    "0e10c968-78fb-11d2-90d4-00c04f79dc55": "Certificate-Enrollment",
    "bf9679c0-0de6-11d0-a285-00aa003049e2": "Self-Membership",
    "72e39547-7b18-11d1-adef-00c04fd8d5cd": "DNS-Host-Name-Attributes",
    "f3a64788-5306-11d1-a9c5-0000f80367c1": "Validated-SPN",
    "b7b1b3dd-ab09-4242-9e30-9980e5d322f7": "Generate-RSoP-Planning",
    "9432c620-033c-4db7-8b58-14ef6d0bf477": "Refresh-Group-Cache",
    "91d67418-0135-4acc-8d79-c08e857cfbec": "SAM-Enumerate-Entire-Domain",
    "b7b1b3de-ab09-4242-9e30-9980e5d322f7": "Generate-RSoP-Logging",
    "b8119fd0-04f6-4762-ab7a-4986c76b3f9a": "Domain-Other-Parameters",
    "e2a36dc9-ae17-47c3-b58b-be34c55ba633": "Create-Inbound-Forest-Trust",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
    "ba33815a-4f93-4c76-87f3-57574bff8109": "Migrate-SID-History",
    "45ec5156-db7e-47bb-b53f-dbeb2d03c40f": "Reanimate-Tombstones",
    "68b1d179-0d15-4d4f-ab71-46152e79a7bc": "Allowed-To-Authenticate",
    "2f16c4a5-b98e-432c-952a-cb388ba33f2e": "DS-Execute-Intentions-Script",
    "f98340fb-7c5b-4cdb-a00b-2ebdfa115a96": "DS-Replication-Monitor-Topology",
    "280f369c-67c7-438e-ae98-1d46f3c6f541": "Update-Password-Not-Required-Bit",
    "ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501": "Unexpire-Password",
    "05c74c5e-4deb-43b4-bd9f-86664c2a7fd5": (
        "Enable-Per-User-Reversibly-Encrypted-Password"
    ),
    "4ecc03fe-ffc0-4947-b630-eb672a8a9dbc": "DS-Query-Self-Quota",
    "91e647de-d96f-4b70-9557-d63ff4f3ccd8": "Private-Information",
    "1131f6ae-9c07-11d1-f79f-00c04fc2dcd2": (
        "Read-Only-Replication-Secret-Synchronization"
    ),
    "ffa6f046-ca4b-4feb-b40d-04dfee722543": "MS-TS-GatewayAccess",
    "5805bc62-bdc9-4428-a5e2-856a0f4c185e": "Terminal-Server-License-Serve",
    "1a60ea8d-58a6-4b20-bcdc-fb71eb8a9ff8": "Reload-SSL-Certificate",
    "89e95b76-444d-4c62-991a-0facbeda640c": (
        "DS-Replication-Get-Changes-In-Filtered-Set"
    ),
    "7726b9d5-a4b4-4288-a6b2-dce952e80a7f": "Run-Protect-Admin-Groups-Task",
    "7c0e2a7c-a419-48e4-a995-10180aad54dd": "Manage-Optional-Features",
    "3e0f7e18-2c7a-4c10-ba82-4d926db99a3e": "DS-Clone-Domain-Controlle",
    "d31a8757-2447-4545-8081-3bb610cacbf2": "Validated-MS-DS-Behavior-Version",
    "80863791-dbe9-4eb8-837e-7f0ab55d9ac7": "Validated-MS-DS-Additional-DNS-Host-Name",
    "a05b8cc2-17bc-4802-a710-e7c15ab866a2": "Certificate-AutoEnrollment",
    "4125c71f-7fac-4ff0-bcb7-f09a41325286": "DS-Set-Owne",
    "88a9933e-e5c8-4f2a-9dd7-2527416b8092": "DS-Bypass-Quota",
    "084c93a2-620d-4879-a836-f0ae47de0e89": "DS-Read-Partition-Secrets",
    "94825a8d-b171-4116-8146-1e34d8f54401": "DS-Write-Partition-Secrets",
    "9b026da6-0d3c-465c-8bee-5199d7165cba": "DS-Validated-Write-Compute",
    "00000000-0000-0000-0000-000000000000": "All-Extended-Rights",
}

EXTENDED_RIGHTS_NAME_MAP = {k: v for v, k in EXTENDED_RIGHTS_MAP.items()}