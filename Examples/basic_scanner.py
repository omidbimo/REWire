from socket import inet_aton, inet_ntoa
import struct
import logging

logging.basicConfig(level=logging.WARNING,
    format="%(asctime)s - %(levelname)-8s <%(name)s> %(message)s")
logger = logging.getLogger(__name__)

import REWire.eip_encapsulation as eip_encap
from REWire.common_packet_format import CPFId
from REWire.unconnected_client import UnconnectedClient
from REWire.rw_socket import UDP, TCP
from REWire.cip_types import *

class BasicScanner():
    def __init__(self, host_ip: str):
        self.host_ip = host_ip

    def discover(self, max_delay_ms=500, echo=False):
        """
        list_identity request via UDP broadcast.
        param: max_delay_ms: the maximum acceptable response delay.
               Note that this value may be adjusted by the scanner to match the protocol
               requirements.
        param: echo: If True, the list of discovered devices is printed to the console.

        return: A list of responses to the broadcasted List Identity request.
                Each response may contain more than one Identity item.
        """
        # TODO: use directed broadcast addresses instead of limited Broadcast address
        broadcast_ip = "255.255.255.255" # Limited broadcast address
        #broadcast_ip = inet_ntoa(struct.pack("!I", (
        #    ~struct.unpack("!I", inet_aton(subnet_mask))[0] & 0xFFFFFFFF |
        #    struct.unpack("!I", inet_aton(self.host_ip))[0])))

        sock = UDP(self.host_ip, broadcast_ip, timeout=(float(max_delay_ms)/1000))
        list_identity_rsp = eip_encap.list_identity(sock, max_delay_ms=max_delay_ms)

        discovered = []
        for device in list_identity_rsp:
            sender_ip = device["address"][0]
            cpf_items = device["cpf_items"]

            discovered.append(cpf_items)
            if echo is True:
                print("Node {} Identity:".format(sender_ip))
                print("-"*30)
                for item in cpf_items:
                    print(item)
                    print()

        return discovered

    def cip_service(self, server_ip, service_id, class_id, instance_id, attribute_id=None,
                    data=BYTES(), rsp_dt=None):
        ucc = UnconnectedClient(eip_encap.EncapSession(TCP(self.host_ip, server_ip)))
        rsp = ucc.cip_service(service_id, class_id, instance_id, attribute_id,
                                        data=data, timeout=6000, rsp_dt=rsp_dt)
        ucc.session.close()
        return rsp

    def get_attributes_all(self, server_ip, class_id, instance_id, rsp_dt=None):
        return self.cip_service(server_ip, 0x01, class_id, instance_id, rsp_dt=rsp_dt)

    def get_attribute_single(self, server_ip, class_id, instance_id, attribute_id,
                             rsp_dt=None):
        return self.cip_service(server_ip, 0x0E, class_id, instance_id, attribute_id,
                                rsp_dt=rsp_dt)

    def set_attribute_single(self, server_ip, class_id, instance_id, attribute_id,
                             data, rsp_dt=None):
        return self.cip_service(server_ip, 0x10, class_id, instance_id, attribute_id,
                                data, rsp_dt=rsp_dt)

if __name__ == "__main__":

    host_ip = "192.168.210.100"
    # Create a new instance of BasicScanner which is an Unconnected Client
    ucc = BasicScanner(host_ip)
    discovered_ips = []
    # This client has a discovery method. It returns a list of CFP_items for each discovered device
    for cpf_items in ucc.discover(max_delay_ms=1000, echo=True):
        # Extract EtherNet/IP node's IP address
        for item in cpf_items:
            if item.type_id == CPFId.CIP_IDENTITY: #List Identity Item
                discovered_ips.append(inet_ntoa(item.sin_addr.pack()))

    for ip_address in discovered_ips:
        # Our BasicScanner opens a session for each service request and closes that session
        # after receiving the response to that service.
        # It's not possible to use a same session for a sequence of services.
        print(f"*** Server {ip_address} ***")
        print("get_attribute_single returns CIP data in bytes format:")
        print(f"Identity instance attribute 7 (Product Name): {ucc.get_attribute_single(ip_address, 1, 1, 7)}")
        print()
        print("get_attributes_all returns CIP data in bytes format:")
        print(f"Identity instance get_attributes_all: {ucc.get_attributes_all(ip_address, 1, 1)}")
        print()
        print("get_attribute_single returns unpacked data when data type is provided:")
        print(f"Identity instance attribute 1 (Vendor Id): {ucc.get_attribute_single(ip_address, 1, 1, 1, rsp_dt=UINT)}")
        print(f"Identity instance attribute 7 (Product Name): {ucc.get_attribute_single(ip_address, 1, 1, 7, rsp_dt=SHORT_STRING)}")
        # Alternative way to call GetAttributeSingle with response data-type provided
        print(f"Identity instance attribute 6 (Serial Number): {ucc.cip_service(ip_address, 0x0E, 1, 1, 6, rsp_dt=UDINT)}")
        print()
