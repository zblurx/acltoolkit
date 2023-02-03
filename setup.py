from importlib.metadata import entry_points
from setuptools import setup

setup(
    name="acltoolkit-ad",
    version="0.2.2",
    author="zblurx",
    url="https://github.com/zblurx/acltoolkit",
    long_description="README.md",
    license="MIT",
    packages=["acltoolkit"],
    install_requires=[
        "asn1crypto==1.5.1",
        "pycryptodome==3.17",
        "impacket==0.10.0",
        "ldap3==2.9.1",
        "pyasn1==0.4.8",
        "dnspython==2.3.0",
    ],
    entry_points={
        "console_scripts":["acltoolkit=acltoolkit.entry:main"],
    },
)
