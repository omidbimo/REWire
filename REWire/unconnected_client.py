from time import time, sleep
import inspect
import random
import logging

import REWire.eip_encapsulation as eip_encap
from REWire.rw_packet import Packet
from REWire.common_packet_format import (
        CPFId,
        NullAddressItem,
        UnconnectedDataItem,
        )

from REWire.explicit_transport import (
        ExplicitTransport,
        MessageRouterRequest,
        MessageRouterResponse,
        )

from REWire.objects.object0x0005 import (
    State,
    TransportClass,
    ProductionTrigger,
    ConnectionInstanceType,
    TransportClassTrigger,
    TransportDirection,
    )

from REWire.common import (
    CIPServiceId,
    CIPObjectId,
    )

from REWire.exceptions import (
    CIP_GeneralStatusCode as GSC,
    CIPError,
    )
from REWire.rw_socket import *
from REWire.rw_socket import DEFAULT_CIPHER_SUITES
from REWire.utils import *
from REWire.cip_types import *


logger = logging.getLogger(__name__)

class UCMMRequest(Packet):
    _fields = (
        ('item_count',   UINT(2)),
        ('address_item', NullAddressItem()),
        ('data_item',    UnconnectedDataItem()),
        )


class UCMMResponse(UCMMRequest):
    pass


class DTLS_UnconnectedEncapPacket(Packet):
    _fields = (
        ('item_count', UINT(1)),
        ('type_id', UINT(CPFId.DTLS_UNCONNECTED_MESSAGE)),
        ('length', UINT(10)),
        ('unconn_msg_type', UINT(1)),
        ('transaction_number', UDINT(0)),
        ('status', UDINT(0)),
        ('unconnected_message', BYTES()),
        )

    def __init__(self, unconnected_message=b''):
        super(DTLS_UnconnectedEncapPacket, self).__init__()
        self.unconnected_message = BYTES(unconnected_message)
        self.length += UINT(len(unconnected_message))


class UnconnectedClient(ExplicitTransport):
    def __init__(self, session):
        super(UnconnectedClient, self).__init__()
        self.session = session

    def __del__(self):
        pass
        #if self.session:
        #    self.session.close()

    @property
    def ip(self):
        return self.session.host_ip

    @property
    def peer_ip(self):
        return self.session.socket.peer_ip

    def cip_service_send_request(self, service_id, class_id, instance_id,
            attribute_id, data=b'', ekey: ELECTRONIC_KEY_SEGMENT=None):

        if self.session:
            self.session.open()

        ucmm_req = UCMMRequest()

        mr_req = MessageRouterRequest(service=service_id)
        if ekey is not None:
            mr_req.request_path += ekey

        mr_req.request_path += RequestPath(class_id, instance_id, attribute_id)
        mr_req.request_data = data

        self.session.seq_number = self.session.seq_number + 1

        if len(mr_req.pack()) > 504: #The maximum size of the MR request packet in the SendRRData
            logger.warning(inspect.currentframe().f_code.co_name +
                "Request ({} bytes) longer than maximum Message-Router size (504 bytes).".format(len(mr_req.pack())))

        ucmm_req.data_item = UnconnectedDataItem(mr_req.pack())

        eip_encap.send_rr_data_send_request(self.session.socket, self.session.handle, payload = ucmm_req.pack(),
                 sender_context = self.session.seq_number, timeout = 0,)

    def cip_service_rcv_response(self, service_id, timeout=3000, rsp_dt=None):
        rsp, _ = eip_encap.send_rr_data_rcv_response(self.session.socket,
                    self.session.seq_number, timeout)

        ucmm_rsp = UCMMResponse.unpack(rsp)

        if ucmm_rsp.data_item.type_id != CPFId.UNCONNECTED_DATA:
            raise Exception("Unexpected CPF in SendRRData response! " +
                "expected:{}, got:{}".format(CPFId.UNCONNECTED_DATA, ucmm_rsp.data_item.type_id))

        if ucmm_rsp.data_item.length != len(ucmm_rsp.data_item.data):
            raise Exception("Unexpected data length in Unconnected message! " +
                            "expected:{}, got:{}".format(ucmm_rsp.data_item.length,
                                                         len(ucmm_rsp.data_item.data) ))

        mr_rsp = MessageRouterResponse.unpack(ucmm_rsp.data_item.data)
        if mr_rsp.service != (service_id | 0x80):
            raise Exception("Unexpected service ID in response! expected:{}, got:{}".format(
                (service_id | 0x80), mr_rsp.service))

        if mr_rsp.general_status != 0:
            raise CIPError(mr_rsp.general_status, mr_rsp.extended_status)

        if rsp_dt is not None:
            return rsp_dt.unpack(mr_rsp.response_data)

        return mr_rsp.response_data


class DTLS_Client(ExplicitTransport):
    def __init__(self, session):
        super(DTLS_Client, self).__init__()
        self.socket = None
        self.connections = []
        self.seq_number = 0

    @property
    def peer_ip(self):
        return self.socket.peer_ip

    def __del__(self):
        self.close()

    def cip_service_send_request(self, service_id, class_id, instance_id,
            attribute_id, data, ekey: ELECTRONIC_KEY_SEGMENT=None):

        if self.session:
            self.session.open()

        mr_req = MessageRouterRequest(service=service_id)
        if ekey is not None:
            mr_req.request_path += ekey

        mr_req.request_path.add_application_path(class_id, instance_id, attribute_id)
        mr_req.request_data = data
        self.seq_number = self.seq_number + 1

        if len(mr_req.pack()) > 504: #The maximum size of the MR request packet in the SendRRData
            logger.warning(inspect.currentframe().f_code.co_name +
                "Request ({} bytes) longer than maximum Message-Router size (504 bytes).".format(len(mr_req.pack())))

        dtls_ucm = DTLS_UnconnectedEncapPacket(mr_req.pack())
        self.socket.send(dtls_ucm.pack())

    def cip_service_rcv_response(self, service_id, timeout=2000, rsp_dt=None):
        t_start = time()
        timeout = float(timeout)/1000
        while True:
            data, _, timestamp = self.socket.receive(timeout)[0]
            timeout = timeout - (time() - t_start)
            dtls_ucm = DTLS_UnconnectedEncapPacket.unpack(data)

            if dtls_ucm.type_id == CPFId.SEQUENCED_ADDRESS:
                #TODO: callback for IO packets
                continue
            if dtls_ucm.type_id != CPFId.DTLS_UNCONNECTED_MESSAGE:
                raise Exception("Unexpected CPF in DTLS response! " +
                    "expected:{}, got:{}".format(CPFId.DTLS_UNCONNECTED_MESSAGE, dtls_ucm.type_id))

            if dtls_ucm.length != len(dtls_ucm.unconn_msg_type) + len(dtls_ucm.transaction_number) + len(dtls_ucm.status) + len(dtls_ucm.unconnected_message):
                raise Exception("Unexpected data length in Unconnected message! " +
                                "expected:{}, got:{}".format(dtls_ucm.length,
                                                             len(dtls_ucm.unconn_msg_type) + len(dtls_ucm.transaction_number) + len(dtls_ucm.status) + len(dtls_ucm.unconnected_message) ))

            mr_rsp = MessageRouterResponse.unpack(dtls_ucm.unconnected_message)

            if mr_rsp.service != (service_id | 0x80):
                raise Exception("Unexpected service ID in response! expected:{}, got:{}".format(
                    (service_id | 0x80), mr_rsp.service))
            if mr_rsp.general_status != 0:
                raise CIPError(mr_rsp.general_status, mr_rsp.extended_status)

            if rsp_dt is not None:
                return rsp_dt.unpack(mr_rsp.response_data._value)

            return mr_rsp.response_data._value
        raise Exception("No response from server!")
