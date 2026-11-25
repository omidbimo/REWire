import logging
logging.basicConfig(level=logging.INFO,
    format="%(asctime)s - %(levelname)-8s <%(name)s> %(message)s")

from OpenSSL import SSL

from REWire import (
    TCP,
    TLS,
    CIPError,
    EncapSession,
    ConnectedClient,
    CIPServiceId,
    CIPObjectId,
)

from REWire.cip_types import *


def connected_messaging_demo(host_ip, server_ip):
    """
    A ConnectedClient wraps an encapsulation session and provides a high-level interface
    for invoking CIP connected explicit messaging services without requiring direct
    interaction with the encapsulation layer.

    Internally, it uses Class3 packets and the encapsulation SendUnitData service
    to communicate with EtherNet/IP devices.

    The ConnectedClient provides the following APIs:
        - cip_service: Invoke any CIP service with full control over the request parameters.
        - get_attribute_single: Read a single attribute from a device.
        - set_attribute_single: Write a single attribute to a device.
        - get_attributes_all: Read multiple attributes of an object from a device.
    """
    print("*** Class3 Connection ***")
    # ConnectedClient requires a session to establish the connection
    cc = ConnectedClient(EncapSession.from_addr(host_ip, server_ip))
    # Calling open() will open the connection by sending a ForwardOpen request to the server
    cc.open()

    # The standard return value of connected services is cip_types.BYTES which is same as python bytes
    print("  Vendor Id:", cc.get_attribute_single(class_id=CIPObjectId.IDENTITY, instance_id=1, attribute_id=1))
    print("  Product Name:", cc.get_attribute_single(CIPObjectId.IDENTITY, 1, 7))

    # Optionally, a cip_type can be provided when invoking the service. The
    # service then attempts to parse the response into the specified type and
    # raises an exception if parsing fails.
    print("  Serial Number:", cc.get_attribute_single(CIPObjectId.IDENTITY, 1, 6, rsp_dt=UDINT))
    print("  Product Name:", cc.get_attribute_single(CIPObjectId.IDENTITY, 1, 7, rsp_dt=SHORT_STRING))

    # Calling close will send a ForwardClose request to the server and closes the connection and conditionally
    # closes the underlying encapsulation session if it's not used by other connections.
    cc.close()

    # An encapsulation session can be shared among multiple connections
    session = EncapSession(TCP(host_ip, server_ip))
    cc1 = ConnectedClient(session)
    cc2 = ConnectedClient(session)
    cc1.open()
    cc2.open()

    print("  Connection1, Serial Number:", cc1.get_attribute_single(CIPObjectId.IDENTITY, 1, 6, rsp_dt=UDINT))
    print("  Connection2, Product Name:", cc2.get_attribute_single(CIPObjectId.IDENTITY, 1, 7, rsp_dt=SHORT_STRING))

    cc1.close()
    cc2.close()

    # Using other services provided by the ConnectedClient
    cc = ConnectedClient(EncapSession.from_addr(host_ip, server_ip))
    cc.open()

    print(f"Setting TCP/IP interface object instance attribute 13(Inactivity timer)...")
    try:
        cc.set_attribute_single(CIPObjectId.TCPIP_INTERFACE, 1, 13, data=bytes([120, 0]))
    except CIPError as ex:
        print(ex)
    # Another way to pass the data
    try:
        cc.set_attribute_single(CIPObjectId.TCPIP_INTERFACE, 1, 13, data=UINT(120))
    except CIPError as ex:
        print(ex)
    # calling Other services
    try:
        # GetAttributesAll of the identity class
        print("  Identity class GetAttributesAll:", cc.get_attributes_all(CIPObjectId.IDENTITY, 0))
        # Alternatively use cip_service to call any cip service.
        print("  Product Name:", cc.cip_service(
                    CIPServiceId.GET_ATTRIBUTE_SINGLE, CIPObjectId.IDENTITY, 1, 7, rsp_dt=SHORT_STRING)
                    )
    except CIPError as ex:
        print(ex)
    cc.close()

    # Use TLS with the library defaults for devices that support CIP Security.
    # The default configuration does not verify the server certificate.
    print("\n*** Secure Class3 Connection ***")
    try:
        cc_sec = ConnectedClient(EncapSession(TLS(host_ip, server_ip)))
        cc_sec.open()
    except (OSError, SSL.Error) as ex:
        print(f"  Skipping TLS messaging for {server_ip}: {ex}")
    else:
        print("  device type:", cc_sec.get_attribute_single(CIPObjectId.IDENTITY, 1, 2, rsp_dt=UINT))
        print("  product name:", cc_sec.get_attribute_single(CIPObjectId.IDENTITY, 1, 7, rsp_dt=SHORT_STRING))
        cc_sec.close()



if __name__ == "__main__":
    host_ip = "192.168.210.102"
    server_ip = "192.168.210.139"
    connected_messaging_demo(host_ip, server_ip)