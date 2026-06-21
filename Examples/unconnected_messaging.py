import logging
logging.basicConfig(level=logging.INFO,
    format="%(asctime)s - %(levelname)-8s <%(name)s> %(message)s")


from REWire import (
    TCP,
    CIPError,
    EncapSession,
    UnconnectedClient,
    CIPServiceId,
    CIPObjectId,
)

from REWire.cip_types import *

logger = logging.getLogger(__name__)

def unconnected_messaging_demo(host_ip, server_ip):
    """
    An UnconnectedClient wraps an encapsulation session and provides a
    high-level interface for invoking CIP explicit messaging services without
    requiring direct interaction with the encapsulation layer.

    Internally, it uses UCMM packets and the encapsulation SendRRData service
    to communicate with EtherNet/IP devices.

    The UnconnectedClient provides the following APIs:
        - cip_service: Invoke any CIP service with full control over the request parameters.
        - get_attribute_single: Read a single attribute from a device.
        - set_attribute_single: Write a single attribute to a device.
        - get_attributes_all: Read multiple attributes of an object from a device.
    """
    print(".:: Unconnected Explicit Communication ::.")

    # Unconnected client requires an encapsulation session to be bale to send the UCMM packages
    ucc = UnconnectedClient(EncapSession(TCP(host_ip, server_ip)))

    # The standard return value of unconnected services is cip_types.BYTES which is equal to python bytes
    print("  Vendor Id:", ucc.get_attribute_single(class_id=CIPObjectId.IDENTITY, instance_id=1, attribute_id=1))
    print("  Product Name:", ucc.get_attribute_single(CIPObjectId.IDENTITY, 1, 7))

    # Optionally, a cip_type can be provided when invoking the service. The
    # service then attempts to parse the response into the specified type and
    # raises an exception if parsing fails.
    print("  Serial Number:", ucc.get_attribute_single(CIPObjectId.IDENTITY, 1, 6, rsp_dt=UDINT))
    print("  Product Name:", ucc.get_attribute_single(CIPObjectId.IDENTITY, 1, 7, rsp_dt=SHORT_STRING))

    # UnconnectedClient supports Electronic keying
    # Electronic Key 4
    try:
        # Adapt the ekey values to your server identity
        print(ucc.get_attribute_single(CIPObjectId.IDENTITY, 1, 2, ekey=ELECTRONIC_KEY_4(0, 12, 100, 1, 1), rsp_dt=UINT))
    except CIPError as ex:
        print(ex)

    # Electronic Key 5
    try:
        # Adapt the ekey values to your server identity
        print(ucc.get_attribute_single(CIPObjectId.IDENTITY, 1, 2, ekey=ELECTRONIC_KEY_5(0, 12, 1, 1, 1, 123456789), rsp_dt=UINT))
    except CIPError as ex:
        print(ex)

    # Electronic Key
    try:
        # Adapt the ekey values to your server identity
        print(ucc.get_attribute_single(CIPObjectId.IDENTITY, 1, 2, ekey=ELECTRONIC_KEY_SEGMENT(4, 0, 12, 1, 1, 1, 123456789), rsp_dt=UINT))
    except CIPError as ex:
        print(ex)

    ucc.session.close()

    # Secure communication is possible when the server supports CIP security
    try:
        # By setting the security parameter to True, a default security configuration will be used
        # to communicate with the server
        sock = TCP(host_ip, server_ip, security=True)
        ucc_sec = UnconnectedClient(EncapSession(sock))

        print("  Device type:", ucc_sec.get_attribute_single(CIPObjectId.IDENTITY, 1, 2, rsp_dt=UINT))
        print("  Product Name:", ucc_sec.get_attribute_single(CIPObjectId.IDENTITY, 1, 7, rsp_dt=SHORT_STRING))

        ucc_sec.session.close()

    except CIPError as ex:
        print(ex)

    # Using other services provided by the UnconnectedClient
    ucc = UnconnectedClient(EncapSession.from_addr(host_ip, server_ip))
    # session.open() is called automatically when invoking UnconnectedClient services.
    # Calling it explicitly is also safe.
    ucc.session.open()

    print(f"Setting TCP/IP interface object instance attribute 13(Inactivity timer)...")
    try:
        ucc.set_attribute_single(CIPObjectId.TCPIP_INTERFACE, 1, 13, data=bytes([120, 0]))
    except CIPError as ex:
        print(ex)
    # Another way to pass the data
    try:
        ucc.set_attribute_single(CIPObjectId.TCPIP_INTERFACE, 1, 13, data=UINT(120))
    except CIPError as ex:
        print(ex)
    # calling Other services
    try:
        # GetAttributesAll of the identity class
        print("  Identity class GetAttributesAll:", ucc.get_attributes_all(CIPObjectId.IDENTITY, 0))
        # Alternatively use cip_service to call any cip service.
        print("  Product Name:", ucc.cip_service(
                    CIPServiceId.GET_ATTRIBUTE_SINGLE, CIPObjectId.IDENTITY, 1, 7, rsp_dt=SHORT_STRING)
                    )
    except CIPError as ex:
        print(ex)
    # Closing the encapsulation session and consequently the TCP stream
    ucc.session.close()

if __name__ == "__main__":
    host_ip = "192.168.210.100"
    server_ip = "192.168.210.132"
    unconnected_messaging_demo(host_ip, server_ip)