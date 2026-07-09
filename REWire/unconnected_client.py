from time import time
import inspect
import random
import logging
logger = logging.getLogger(__name__)

from . import eip_encapsulation as eip_encap
from .rw_packet import Packet
from .common_packet_format import (
        CPF,
        CPFId,
        NullAddressItem,
        UnconnectedDataItem,
        )

from .explicit_transport import (
        ExplicitTransport,
        MessageRouterRequest,
        MessageRouterResponse,
        )

from .objects.object0x0005 import (
    State,
    TransportClass,
    ProductionTrigger,
    ConnectionInstanceType,
    TransportClassTrigger,
    TransportDirection,
    )

from .common import (
    CIPGeneralStatus as GSC,
    CIPServiceId,
    CIPObjectId,
    )

from .exceptions import CIPError
from .cip_types import *


class UCMMPacket(Packet):
    _fields = (
        ('item_count',   UINT(2)),
        ('address_item', NullAddressItem()),
        ('data_item',    UnconnectedDataItem()),
        )


class UnconnectedClient(ExplicitTransport):
    def __init__(self, session):
        super(UnconnectedClient, self).__init__()
        self.session = session

    def __del__(self):
        pass
        #if self.session:
        #    self.session.close()

    @classmethod
    def from_addr(cls, host_ip, server_ip):
        return cls(eip_encap.EncapSession.from_addr(host_ip, server_ip))

    @property
    def ip(self):
        return self.session.host_ip

    @property
    def peer_ip(self):
        return self.session.socket.peer_ip

    def open(self):
        self.session.open()

    def close(self):
        self.session.close()

    def cip_service_send_request(self, service_id, class_id, instance_id,
            attribute_id, data=b'', ekey: ELECTRONIC_KEY_SEGMENT=None):

        if self.session:
            self.session.open()
        else:
            raise Exception("Unconnected Client instance is not valid anymore!")
        mr_req = MessageRouterRequest(service=service_id)
        if ekey is not None:
            mr_req.request_path += ekey

        mr_req.request_path += RequestPath(class_id, instance_id, attribute_id)
        mr_req.request_data = data

        self.session.seq_number = self.session.seq_number + 1

        if len(mr_req.pack()) > 504: #The maximum size of the MR request packet in the SendRRData
            logger.warning(inspect.currentframe().f_code.co_name +
                "Request ({} bytes) longer than maximum Message-Router size (504 bytes).".format(len(mr_req.pack())))

        ucmm_req = UCMMPacket(data_item=UnconnectedDataItem(data=mr_req.pack(), length=len(mr_req.pack())))
        eip_encap.send_rr_data( self.session.socket,
                                self.session.handle,
                                sender_context = self.session.seq_number,
                                payload = ucmm_req.pack(),
                                )

    def cip_service_rcv_response(self, service_id, timeout=3000):
        """

        Note: If there are any SocketAddress items in the response,
        """
        rsp, _ = eip_encap.rcv_rr_data(self.session.socket, self.session.seq_number, timeout)
        rsp_cpf = CPF.unpack(rsp)

        rsp_data_item = rsp_cpf.get_item(CPFId.UNCONNECTED_DATA)
        if rsp_data_item:
            if rsp_data_item.type_id != CPFId.UNCONNECTED_DATA:
                raise Exception("Unexpected CPF in SendRRData response! " +
                            f"expected:{CPFId.UNCONNECTED_DATA}, got:{rsp_data_item.type_id}")

            if rsp_data_item.length != len(rsp_data_item.data):
                raise Exception("Unexpected data length in Unconnected message! " +
                            f"expected:{rsp_data_item.length}, got:{len(rsp_data_item.data)}")

            rsp_mr = MessageRouterResponse.unpack(rsp_data_item.data)
        else:
            raise Exception("No CPF UnconnectedDataItem in the response!")

        if rsp_mr.service != (service_id | 0x80):
            raise Exception("Unexpected service ID in response!" +
                            f"expected:{(service_id | 0x80)}, got:{rsp_mr.service}")

        if rsp_mr.general_status != 0:
            raise CIPError(rsp_mr.general_status, rsp_mr.extended_status)

        if len(rsp_cpf) > 2:
            return (rsp_mr.response_data,
                    rsp_cpf.get_item(CPFId.SOCKADDR_INFO_O2T),
                    rsp_cpf.get_item(CPFId.SOCKADDR_INFO_T2O),
                    )

        return rsp_mr.response_data



