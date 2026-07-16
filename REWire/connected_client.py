import random
from dataclasses import dataclass
import logging
logger = logging.getLogger(__name__)

from .rw_packet import Packet
from . import eip_encapsulation as eip_encap
from .rw_watchdog import WatchdogTimer
from .common_packet_format import (
    CPF,
    CPFId,
    ConnectedAddressItem,
    ConnectedDataItem,
    )

from .explicit_transport import (
    ExplicitTransport,
    MessageRouterRequest,
    MessageRouterResponse,
    )

from .objects.object0x0006 import (
    NetworkConnectionParameters,
    ConnectionType,
    Priority,
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
    CIPServiceId,
    CIPObjectId,
    CIPGeneralStatus as GSC,
    )

from .objects.cip_object import CIPObjectFactory as CIPObject
from .exceptions import CIPError
from .unconnected_client import UnconnectedClient
from .cip_types import *



__all__ = [
        "ConnectedClient",
        ]

class ExplicitConnectedPacket(Packet):
    _fields = (
        ('item_count',   UINT(2)),
        ('address_item', ConnectedAddressItem()),
        ('data_item',    ConnectedDataItem()),
        )


class Class3PDU(Packet):
    _fields = (
        ("sequence_count", UINT(0)),
        ("payload", BYTES()),
        )


@dataclass
class ConnectionTriad:
    connection_serial_number: int=0
    originator_serial_number: int=0
    originator_vendor_id: int=0

    def __str__(self):
        return (f"(Vendor_Id:{self.originator_vendor_id}, Originator_SN:{self.originator_serial_number}, "
                f"SN:0x{self.connection_serial_number:04X})")

    def __repr__(self):
        return (f"ConnectionTriad("
                f"originator_vendor_id:{self.originator_vendor_id}"
                f", connection_serial_number:0x{self.connection_serial_number:04X}"
                f"originator_serial_number:{self.originator_serial_number})")

    def __hash__(self):
        return hash((self.originator_vendor_id, self.originator_serial_number, self.connection_serial_number))

class ConnectedClient(ExplicitTransport):

    def __init__(self,
            session: eip_encap.EncapSession,
            o2t_rpi = 1500000, # uSec resolution 1500x4 -> 6 sec
            t2o_rpi = 1500000, # uSec resolution 1500x4 -> 6 sec
            timeout_multiplier = 0, # 4x RPI: connection timeout
            o2t_size = 511,
            t2o_size = 511,
            o2t_prio = 0,
            t2o_prio = 0,
            vendor_id = 65535,
            originator_serial_number = 0xC0FFEE,
            ekey: ELECTRONIC_KEY_SEGMENT = None,
            ucmm_timeout = 5000, # milliseconds
            ):
        """


        """
        super().__init__()

        self.o2t_rpi = o2t_rpi
        self.t2o_rpi = t2o_rpi
        self.timeout_multiplier = timeout_multiplier
        self.o2t_size = o2t_size
        self.t2o_size = t2o_size
        self.originator_vendor_id = vendor_id
        self.originator_serial_number = originator_serial_number
        self.ekey = ekey
        self.connection_serial_number = 0
        self.ucmm_timeout = ucmm_timeout
        self.isconnected = False
        self.seq_counter = UINT(0)
        self.session = session
        self.cip_producer_connection_id = 0
        self.watchdog = None

    @classmethod
    def from_addr(cls, host_ip, server_ip, **kwargs):
        return cls(eip_encap.EncapSession.from_addr(host_ip, server_ip), kwargs)

    def open(self):
        transport_class_and_trigger = TransportClassTrigger(
                TransportClass.CLASS3,
                ProductionTrigger.APPLICATION_OBJECT,
                TransportDirection.SERVER
                )

        # 2^tick_time * timeout_ticks = timeout mS
        tick_time = 0
        while (2**tick_time)*255 < self.ucmm_timeout:
            tick_time += 1


        connection_path = RequestPath()
        if self.ekey is not None:
            connection_path += self.ekey
        # fwd_open_req.connection_path has type of PaddedEPATH
        connection_path += CLASS_ID_SEGMENT(CIPObjectId.MESSAGE_ROUTER)
        connection_path += INSTANCE_ID_SEGMENT(1)

        cm = CIPObject(UnconnectedClient(self.session), 6)

        o2t_conn_params = NetworkConnectionParameters(
            connection_size = self.o2t_size,
            fixed_variable  = True,
            priority        = Priority.LOW,
            connection_type = ConnectionType.POINT2POINT,
            redundant_owner = False,
            )

        t2o_conn_params = NetworkConnectionParameters(
            connection_size = self.t2o_size,
            fixed_variable  = True,
            priority        = Priority.LOW,
            connection_type = ConnectionType.POINT2POINT,
            redundant_owner = False,
            )

        if self.o2t_size <= 511 and self.t2o_size <= 511:

            o2t_api, t2o_api, connection_serial_number, o2t_network_connection_id, t2o_network_connection_id = cm.forward_open(
                        time_tick = tick_time,
                        timeout_ticks = self.ucmm_timeout//(2**tick_time),
                        o2t_network_connection_id = random.randint(0, 0xFFFFFFFF),
                        t2o_network_connection_id = random.randint(0, 0xFFFFFFFF),
                        connection_serial_number = random.randint(0, 0xFFFF), #self.conn_sng.new(),
                        originator_vendor_id = self.originator_vendor_id,
                        originator_serial_number = self.originator_serial_number,
                        connection_timeout_multiplier = self.timeout_multiplier,
                        o2t_rpi = self.o2t_rpi,
                        o2t_network_connection_parameters = o2t_conn_params,
                        t2o_rpi = self.t2o_rpi,
                        t2o_network_connection_parameters = t2o_conn_params,
                        transport_class_and_trigger = transport_class_and_trigger,
                        connection_path = connection_path,
                        )

        else: # using LargFwdOpen
            o2t_api, t2o_api, connection_serial_number, o2t_network_connection_id, t2o_network_connection_id = cm.large_forward_open(
                        time_tick = tick_time,
                        timeout_ticks = self.ucmm_timeout//(2**tick_time),
                        o2t_network_connection_id = random.randint(0, 0xFFFFFFFF),
                        t2o_network_connection_id = random.randint(0, 0xFFFFFFFF),
                        connection_serial_number = random.randint(0, 0xFFFF), #self.conn_sng.new(),
                        originator_vendor_id = self.originator_vendor_id,
                        originator_serial_number = self.originator_serial_number,
                        connection_timeout_multiplier = self.timeout_multiplier,
                        o2t_rpi = self.o2t_rpi,
                        o2t_network_connection_parameters = o2t_conn_params,
                        t2o_rpi = self.t2o_rpi,
                        t2o_network_connection_parameters = t2o_conn_params,
                        transport_class_and_trigger = transport_class_and_trigger,
                        connection_path = connection_path,
                        )

        self.connection_serial_number = connection_serial_number
        self.cip_producer_connection_id = o2t_network_connection_id
        self.cip_consumer_connection_id = t2o_network_connection_id
        self.connection_timeout = (((1 << self.timeout_multiplier) * 4) * t2o_api) / 1000000
        self.watchdog = WatchdogTimer(timeout=self.connection_timeout, on_timeout=self.handle_timeout)
        self.isconnected = True
        self.session.add_owner(self)
        logger.info(f"Class 3 connection{self.connection_triad} is opened.")

    def close(self):
        if self.watchdog:
            self.watchdog.stop()

        if self.session is None or self.session.peer_ip is None:
            logger.error(f"No active session to close the connection(SN:0x{self.connection_serial_number:04X}, "
                     f"Vendor_Id:{self.originator_vendor_id}, Originator_SN:{self.originator_serial_number}).")
            if self.session:
                self.session.remove_owner(self)
                self.session.close()
            self.cleanup()
            return

        # 2^tick_time * timeout_ticks = timeout mS
        tick_time = 0
        while (2**tick_time)*255 < self.ucmm_timeout:
            tick_time += 1

        cm = CIPObject(UnconnectedClient(self.session), 6)

        cm.forward_close(tick_time,
                         self.ucmm_timeout//(2**tick_time),
                         self.connection_serial_number,
                         self.originator_vendor_id,
                         self.originator_serial_number)

        logger.info(f"Class 3 connection{self.connection_triad} is closed.")

        if self.session:
            self.session.remove_owner(self)
            self.session.close()
        self.cleanup()

    def cip_service_send_request(self, service_id : int, class_id, instance_id, attribute_id, data, *args, **keyargs):
        req = MessageRouterRequest(service=service_id)
        req.request_path = RequestPath(class_id, instance_id, attribute_id)
        req.request_data = data
        self.seq_counter = UINT((int(self.seq_counter) + 1) & 0XFFFF)

        req_pdu = Class3PDU(self.seq_counter, req.pack())

        if not self.session.handle:
            self.session.open()

        req_explicit = ExplicitConnectedPacket(
                address_item=ConnectedAddressItem(connection_identifier=self.cip_producer_connection_id),
                data_item=ConnectedDataItem(data=req_pdu.pack(), length=len(req_pdu.pack())),
                )

        self.session.seq_number += 1
        eip_encap.send_unit_data(self.session.socket,
                                self.session.handle,
                                sender_context=self.session.seq_number,
                                payload=req_explicit.pack(),
                              )
        self.watchdog.reset()

    def cip_service_rcv_response(self, service_id : int, expected_gsc=None, expected_esc=None, timeout=5000):

        rsp, _  = eip_encap.rcv_unit_data(self.session.socket,
                                        self.session.seq_number,
                                        timeout)

        rsp_cpf = CPF.unpack(rsp)
        rsp_addr_item = rsp_cpf.get_item(CPFId.CONNECTED_ADDRESS)
        if rsp_addr_item is None:
            raise Exception("No CPF CconnectedAddressItem in the response!")

        if rsp_addr_item.type_id != CPFId.CONNECTED_ADDRESS:
            raise Exception("Unexpected CPF in SendUnitData response! " +
                            f"expected:{CPFId.CONNECTED_ADDRESS}, got:{rsp_addr_item.type_id}")

        if rsp_addr_item.length != 4:
            raise Exception("Unexpected data length in Connected message! " +
                            f"expected:4 bytes, got:{len(rsp_addr_item.data)} bytes.")

        if rsp_addr_item.connection_identifier != self.cip_consumer_connection_id:
            raise Exception("Unexpected Connection Id in SendUnitData response! " +
                            f"expected:{self.cip_consumer_connection_id}, got:{rsp_addr_item.connection_identifier}")

        rsp_data_item = rsp_cpf.get_item(CPFId.CONNECTED_DATA)
        if rsp_data_item is None:
            raise Exception("No CPF CconnectedDataItem in the response!")

        if rsp_data_item.type_id != CPFId.CONNECTED_DATA:
            raise Exception("Unexpected CPF in SendUnitData response! " +
                            f"expected:{CPFId.CONNECTED_DATA}, got:{rsp_data_item.type_id}")

        if rsp_data_item.length != len(rsp_data_item.data):
            raise Exception("Unexpected data length in Connected message! " +
                            f"expected:{rsp_data_item.length}, got:{len(rsp_data_item.data)}")

        class3_pdu = Class3PDU.unpack(rsp_data_item.data)

        if class3_pdu.sequence_count != self.seq_counter:
            logger.error("Unexpected sequence counter in response!" +
                         f" expected:{self.seq_counter}, got:{class3_pdu.sequence_count}")

        rsp_mr = MessageRouterResponse.unpack(class3_pdu.payload)

        if rsp_mr.service != (service_id | 0x80):   #TODO: correct handling?
            logger.error("Unexpected service ID in response!" +
                         f"expected:0x{(service_id | 0x80):X}, got:0x{rsp_mr.service:X}")

        if rsp_mr.general_status != GSC.SUCCESS:
            raise CIPError(rsp_mr.general_status, rsp_mr.extended_status)

        self.watchdog.reset()

        if len(rsp_cpf) > 2:
            # The response CPF may contain two Socket Address Info items.
            # Pass these, together with the MR data, to the upper layer
            # which may be handling a Forward_Open response.
            return (rsp_mr.response_data,
                    rsp_cpf.get_item(CPFId.SOCKADDR_INFO_O2T),
                    rsp_cpf.get_item(CPFId.SOCKADDR_INFO_T2O),
                    )

        return rsp_mr.response_data

    def handle_timeout(self):
        self.watchdog.stop()
        if self.session:
            self.session.remove_owner(self)
            self.session.close()
        logger.error(f"Class 3 Connection Timeout! Connection (SN:0x{self.connection_serial_number:04X}, "
                     f"Vendor_Id:{self.originator_vendor_id}, Originator_SN:{self.originator_serial_number}) closed.")
        self.cleanup()

    @property
    def connection_triad(self):
        return ConnectionTriad(
                    self.connection_serial_number,
                    self.originator_serial_number,
                    self.originator_vendor_id,
                    )

    def cleanup(self):
        self.watchdog = None
        self.session = None
        self.cip_producer_connection_id = None
        self.cip_consumer_connection_id = None
        self.isconnected = False

    def __del__(self):
        if self.session:
            self.session.remove_owner(self)

    def __repr__(self):
        return "peer_ip:{}, {}".format(self.session.peer_ip, self.connection_triad)
