"""
Can be used to query the agent example:
examples/v3arch/asyncore/agent/cmdrsp/multiple-usm-users.py
"""

import asyncio
from pysnmp.hlapi.auth import usmDESPrivProtocol, usmHMACMD5AuthProtocol, usmHMACSHAAuthProtocol
from pysnmp.smi.rfc1902 import ObjectIdentity, ObjectType
from pysnmp.hlapi.asyncio import getCmd,UdpTransportTarget,ContextData, \
                                 UsmUserData
from pysnmp.entity import engine
import sys

async def run(username:str):
    snmpEngine = engine.SnmpEngine()
    auth = None
    match username:
        case 'usr-none-none':
            auth = UsmUserData(userName=username)
        case 'usr-sha-none':
            # user: usr-sha-none, auth: SHA, priv NONE
            # config.addV3User(snmpEngine, "usr-sha-none", config.usmHMACSHAAuthProtocol, "authkey1")
            # config.addTargetParams(snmpEngine, "my-creds", "usr-sha-none", "authNoPriv")
            auth = UsmUserData(
                userName=username,
                authKey='authkey1',
                authProtocol=usmHMACSHAAuthProtocol
            )
        case 'usr-md5-des':
            # user: usr-md5-des, auth: MD5, priv DES
            # config.addV3User(snmpEngine,"usr-md5-des",config.usmHMACMD5AuthProtocol,"authkey1",config.usmDESPrivProtocol,"privkey1",)
            auth = UsmUserData(
                userName=username,
                authKey='authkey1',
                authProtocol=usmHMACMD5AuthProtocol,
                privKey='privkey1',
                privProtocol=usmDESPrivProtocol)  # https://www.yaklin.ca/2022/01/19/secure-query-with-snmpv3-and-pysnmp.html
        case _:
            print(f"Urecognized username: '{username}', aborting")
            return
    """
        case 'usr-none-des':
            # user: usr-none-des, auth: NONE, priv DES
            Illegal combination:
        File "/workspaces/pysnmp/env/lib/python3.10/site-packages/pysnmp/hlapi/auth.py", line 377, in __init__
            raise error.PySnmpError('Privacy implies authenticity')
    """


    errorIndication, errorStatus, errorIndex, varBinds = await getCmd(
        snmpEngine,
        # CommunityData('public'),
        auth,
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

if (args_count := len(sys.argv)) > 2:
    print(f"One argument expected, got {args_count - 1}")
    raise SystemExit(2)
elif args_count < 2:
    print("You must specify the username")
    raise SystemExit(2)

asyncio.run(run(sys.argv[1]))
