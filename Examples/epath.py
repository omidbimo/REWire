import logging
logging.basicConfig(level=logging.INFO,
    format="%(asctime)s - %(levelname)-8s <%(name)s> %(message)s")

from REWire.common import CIPGeneralStatus as GSC
from REWire import (
    TCP,
    CIPError,
    EncapSession,
    UnconnectedClient,
    CIPServiceId,
    CIPObjectId,
)

from REWire.cip_types import (
    PaddedEPATH,
    RequestPath,
    ELECTRONIC_KEY_4,
    ELECTRONIC_KEY_5,
    CLASS_ID_SEGMENT,
    INSTANCE_ID_SEGMENT,
    ATTRIBUTE_ID_SEGMENT,
    CONNECTION_POINT_SEGMENT,
)

logger = logging.getLogger(__name__)

def epath_demo(host_ip, server_ip):
    print("\n.::: EPATH demo :::.")
    # Empty padded EPATH
    path = PaddedEPATH()
    print("Empty EPATH:", repr(path))
    # Add electronic key to the EPATH
    path += ELECTRONIC_KEY_4(vendor_id=283, device_type=12, product_code=771, major_rev=1, minor_rev=2)
    print("EPATH:", repr(path))
    # Add some logical segments to the EPATH
    path += CLASS_ID_SEGMENT(0x37)
    path += INSTANCE_ID_SEGMENT(0x110)
    path += ATTRIBUTE_ID_SEGMENT(0x0C)
    print("EPATH:", repr(path))

    # Request EPATH is a padded EPATH
    path = RequestPath(class_id=0x109, instance_id=1, attribute_id=4, ekey=ELECTRONIC_KEY_4(283, 12, 257, 1, 1))
    print("RequestPath:", f"{path}")

    path = RequestPath()
    path += ELECTRONIC_KEY_5(283, 12, 257, 1, 1, 123456789)
    path += RequestPath(class_id=0x109, instance_id=1, attribute_id=4)
    print("RequestPath:", f"{path}")


    # Creating a padded EPATH from bytes
    path = PaddedEPATH.unpack(b"\x02\x20\x04\x24\x01")
    print(repr(path))
    # Add connection points to the EPATH
    path += CONNECTION_POINT_SEGMENT(0x65)
    path += CONNECTION_POINT_SEGMENT(0x64)
    print(repr(path))
    print(path)

    # Getting an attribute containing an EPATH
    ucc = UnconnectedClient(EncapSession(TCP(host_ip, server_ip)))
    # Getting Active Device Certificate from EtherNet/IP security object
    try:
        device_cert = ucc.get_attribute_single(0x5E, 1, 6)
        path = EPATH(path=device_cert[1:])
        print("Active Device Certificate File EPATH:", path)
        print("packed EPATH: [{}]".format(" ".join("{:02X}".format(octet) for octet in path.pack())))
    except CIPError as err:
        if err.GeneralStatus == GSC.PATH_DESTINATION_UNKNOWN:
            print("Adapter doesn't support CIP Security.")
        else:
            raise(err)

if __name__ == "__main__":
    host_ip = "192.168.210.100"
    server_ip = "192.168.210.133"
    epath_demo(host_ip, server_ip)