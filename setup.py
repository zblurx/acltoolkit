from importlib.metadata import entry_points
from setuptools import setup

setup(
    name="acltlk",
    version="0.0.1",
    author="zblurx",
    url="https://github.com/zblurx/acltlk",
    long_description="README.md",
    packages=["acltlk"],
    install_requires=[
        "asn1crypto",
        "pycryptodome",
        "impacket",
        "ldap3",
        "pyasn1",
        "dnspython",
    ],
    entry_points={
        "console_scripts":["acltlk=acltlk.entry:main"],
    },
)