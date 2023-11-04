"""
Can be used to query the agent example:
examples/v3arch/asyncore/agent/cmdrsp/multiple-usm-users.py
"""

import asyncio
from pysnmp.smi.rfc1902 import ObjectIdentity, ObjectType
from pysnmp.hlapi.asyncio import getCmd,SnmpEngine,CommunityData,UdpTransportTarget,ContextData, \
                                 UsmUserData


async def run():
    errorIndication, errorStatus, errorIndex, varBinds = await getCmd(
        SnmpEngine(),
        # CommunityData('public'),
        UsmUserData('usr-none-none'),
        UdpTransportTarget(('127.0.0.1', 1161)),
        # UdpTransportTarget(('demo.pysnmp.com', 161)),
        ContextData(),
        ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0))
    )

    if errorIndication:
        print(errorIndication)
    elif errorStatus:
        print(
            "{} at {}".format(
                errorStatus.prettyPrint(),
                errorIndex and varBinds[int(errorIndex) - 1][0] or "?",
            )
        )
    else:
        for varBind in varBinds:
            print(" = ".join([x.prettyPrint() for x in varBind]))



asyncio.run(run())
