#!/usr/bin/env python

from distutils.core import setup

setup(name="pysnmp",
      version="4.0.0a",
      description="SNMP framework for Python",
      author="Ilya Etingof",
      author_email="ilya@glas.net ",
      url="http://sourceforge.net/projects/pysnmp/",
      packages = [ 'pysnmp',
                   'pysnmp.v4',
                   'pysnmp.v4.asn1',
                   'pysnmp.v4.asn1.encoding',
                   'pysnmp.v4.asn1.encoding.ber',
                   'pysnmp.v4.smi',
                   'pysnmp.v4.smi.mibs',
                   'pysnmp.v4.carrier',
                   'pysnmp.v4.carrier.asynsock',
                   'pysnmp.v4.carrier.asynsock.dgram',
                   'pysnmp.v4.proto',
                   'pysnmp.v4.proto.msgproc',
                   'pysnmp.v4.proto.secmod',
                   'pysnmp.v4.proto.omni' ],
      license="BSD"
      )
