from importlib.metadata import entry_points
from setuptools import setup

setup(
    name="acltoolkit",
    version="0.0.1",
    author="zblurx",
    url="https://github.com/zblurx/acltoolkit",
    long_description="README.md",
    license="MIT",
    packages=["acltoolkit"],
    install_requires=[
        "asn1crypto",
        "pycryptodome",
        "impacket",
        "ldap3",
        "pyasn1",
        "dnspython",
    ],
    entry_points={
        "console_scripts":["acltoolkit=acltoolkit.entry:main"],
    },
)