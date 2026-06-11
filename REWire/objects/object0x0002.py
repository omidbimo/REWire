from REWire.cip_types import *
from REWire.cip_object import *
from REWire.common     import *
from REWire.unconnected_client import UnconnectedClient
from REWire.explicit_transport import (
        MessageRouterRequest,
        MessageRouterResponse,
        )
import logging
logger = logging.getLogger(__name__)


class Object0x0002_Services(CIPServiceId):
    SYMBOLIC_TRANSLATION =  0x4B
    SEND_RECEIVE_FRAGMENT = 0x4C


class FragmentationFlags(EnumThatWorks):
    FIRST = 0x01
    LAST  = 0x02
    ABORT = 0x04


class SendReceiveFragmentPacket(Packet):
    _fields = (
        ("fragmentation_version",   USINT(1)),
        ("fragmentation_flags",     BYTE(FragmentationFlags.FIRST)),
        ("reserved",                UINT(0)),
        ("info",                    UDINT(0)),
        ("embedded_data",           BYTES()),
        )

class ObjectList(Packet):
    _fields = (
        ("number",      UINT(0)),
        ("classes",     ARRAY(dtype=UINT)),
        )

    @classmethod
    def dissect(cls, bstream):
        classes = ARRAY(dtype=UINT)
        number, bstream = Packet.dissect.uint(bstream)
        for _ in range(number):
            class_id, bstream = UINT.dissect(bstream)
            classes += UINT(class_id)
        return classes, bstream

    #def __str__(self):
    #    return "\n".join(("Instance Id.: {}\n".format(entry.instance_id) +
    #                      "    Instance name: \"{}\"\n".format(entry.instance_name) +
    #                      "    File name: \"{}\"".format(entry.file_name))
    #                      for entry in self._entries)

class Object0x0002_Rev1(CIP_ObjectCommon):
    class_id = 0x02
    class_name = "Message Router Object"
    services = Object0x0002_Services

    _class_attributes = CIP_class_attributes

    _instance_attributes = (
        (1,  "object_list",         ObjectList),
        (2,  "number_available",    UINT),
        (3,  "number_active",       UINT),
        (4,  "active_connections",  ARRAY),
        )

    def send_receive_fragment(self, embedded_service_id, embedded_class_id,
            embedded_instance_id, embedded_attribute_id=None, embedded_data=b'', rsp_dt=None):
        if isinstance(self.client, UnconnectedClient):
            logger.wrning("send_receive_fragment service is not possible with unconnected requests!")
        embed_req = MessageRouterRequest(service=embedded_service_id)
        embed_req.request_path.add_application_path(embedded_class_id,
                embedded_instance_id, embedded_attribute_id)
        embed_req.request_data = embedded_data
        embed_req = embed_req.pack()
        # 2 bytes: sequence_count
        # 1 byte: service_id
        # 1 byte: path_size
        # 4 bytes: request_path (MR request)
        # 1 byte: fragmentation_version
        # 1 byte: fragmentation_flags
        # 2 bytes: reserved
        # 4 bytes: info
        max_fragment_size = self.client.o2t_size - 16
        fragmentation_flags = 0
        fragment_offset = 0
        last_packet = False
        while not (fragmentation_flags & FragmentationFlags.LAST):
            fragment_size = min(max_fragment_size, len(embed_req)-fragment_offset)
            if len(embed_req) <= max_fragment_size:
                info = len(embed_req)
                fragmentation_flags = FragmentationFlags.FIRST | FragmentationFlags.LAST
                last_packet = True
            elif fragment_offset == 0:
                info = len(embed_req)
                fragmentation_flags = FragmentationFlags.FIRST
            elif fragment_offset < len(embed_req):
                info = fragment_offset,
                fragmentation_flags = 0
            else:
                info = fragment_offset,
                fragmentation_flags = FragmentationFlags.LAST
                last_packet = True

            fragment_data = embed_req[fragment_offset:fragment_offset+fragment_size]
            fragment_offset += fragment_size

            network_rsp = self.send_receive_fragment_step(1, fragmentation_flags,
                    info, fragment_data)

        embedded_data = BYTES()
        embedded_data_size = 0

        while True:
            fragmentation_rsp = SendReceiveFragmentPacket().unpack(network_rsp)

            if fragmentation_rsp.fragmentation_flags & FragmentationFlags.FIRST:
                if len(embedded_data) != 0:
                    raise Exception("Unexpected FIRST packet instead of a MIDDLE or a LAST packet.")
                embedded_data_size = fragmentation_rsp.info
            embedded_data += fragmentation_rsp.embedded_data
            if fragmentation_rsp.fragmentation_flags & FragmentationFlags.LAST:
                if len(embedded_data) != embedded_data_size:
                    raise Exception("Response data size mismatch! expected:{} bytes, got:{} bytes".format(rsp_size, rsp_size))
                break
            network_rsp = self.send_receive_fragment_step(1, 0, 0, 0)

        rsp = MessageRouterResponse().unpack(embedded_data)

        if rsp.service != embedded_service_id | 0x80:
            raise Exception("Unexpected service id in response to a send_receive_fragment_request."
                    "expected:0x{:02X}, got:0x{:02X}".format(embedded_service_id | 0x80, rsp.service))
        if rsp.general_status != 0:
            if rsp.general_status == 0x1E:
                raise CIPError(rsp.general_status, rsp.extended_status)

        if rsp_dt:
            return rsp_dt().unpack(rsp.response_data)

        return rsp.response_data

    def send_receive_fragment_step(self, version, flags, info, fragment_data):
        req = SendReceiveFragmentPacket(version, flags, info=info,
                embedded_data=fragment_data)
        return self.client.cip_service(self.services.SEND_RECEIVE_FRAGMENT,
                self.class_id, instance_id=1, data=req.pack())