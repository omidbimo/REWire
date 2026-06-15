from time import sleep
import inspect
import random
from typing import Any, Optional, Tuple, Union
from dataclasses import dataclass
import logging

import REWire.eip_encapsulation as eip_encap
from REWire.rw_packet import Packet
from REWire.rw_watchdog import WatchdogTimer
from REWire.common_packet_format import (
    CPF,
    CPFId,
    ConnectedAddressItem,
    ConnectedDataItem,
    )

from REWire.cip_types import *
from REWire.utils import *
from REWire.explicit_transport import ExplicitTransport, MessageRouterRequest, MessageRouterResponse

from REWire.objects.object0x0006 import (
    NetworkConnectionParameters,
    ConnectionType,
    Priority,
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

from REWire.cip_objects import *

from REWire.exceptions import (
    CIP_GeneralStatusCode as GSC,
    CIPError,
    )
from REWire.unconnected_client import UnconnectedClient

logger = logging.getLogger(__name__)

__all__ = [
        "ConnectedClient",
        ]

class Class2_3_PDU(Packet):
    _fields = (
        ("sequence_count", UINT(0)),
        ("payload", BYTES()),
        )


class Class2_3_Packet(Packet):
    _fields = (
                ('item_count',   UINT(2)),
                ('address_item', ConnectedAddressItem()),
                ('data_item',    ConnectedDataItem()),
                )

    def __init__(self, connection_id=0, data=b""):
        super().__init__(address_item=ConnectedAddressItem(connection_identifier=connection_id), data_item=data)


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


class ConnectedClient(ExplicitTransport):

    def __init__(self,
            session,
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
        super(ConnectedClient, self).__init__()

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
        self.cip_produced_connection_id = 0
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

        self.session.add_owner(self)
        ucc = UnconnectedClient(self.session)
        cm = CIP_Object(ucc, 6)

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
        self.cip_produced_connection_id = o2t_network_connection_id
        self.cip_consumed_connection_id = t2o_network_connection_id
        self.connection_timeout = (((1 << self.timeout_multiplier) * 4) * t2o_api) / 1000000
        self.watchdog = WatchdogTimer(timeout=self.connection_timeout, on_timeout=self.handle_timeout)
        self.isconnected = True

        logger.info(f"Connection({self.connection_triad}) is opened.")

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

        ucc = UnconnectedClient(self.session)
        cm = CIP_Object(ucc, 6)

        cm.forward_close(tick_time,
                         self.ucmm_timeout//(2**tick_time),
                         self.connection_serial_number,
                         self.originator_vendor_id,
                         self.originator_serial_number)

        logger.info(f"Connection{self.connection_triad} is closed.")

        if self.session:
            self.session.remove_owner(self)
            self.session.close()
        self.cleanup()

    def cip_service_send_request(self, service_id : int, class_id, instance_id, attribute_id, data, *args, **keyargs):
        req = MessageRouterRequest(service=service_id)
        req.request_path = RequestPath(class_id, instance_id, attribute_id)
        req.request_data = data
        self.seq_counter = UINT((self.seq_counter + 1) & 0XFFFF)

        cmsg = Class2_3_Packet(self.cip_produced_connection_id,
            self.seq_counter.pack() + req.pack())

        if self.session.handle is None:
            raise Exception("No active session to send the connection request!")

        self.session.seq_number += 1
        eip_encap.send_unit_data_send_request(self.session.socket, self.session.handle,
                payload=cmsg.pack(), sender_context=self.session.seq_number,)

    def cip_service_rcv_response(self, service_id : int, expected_gsc=None, expected_esc=None, timeout=5000, rsp_dt=None):
        rsp, _  = eip_encap.send_unit_data_rcv_response(self.session.socket,
                 self.session.seq_number, timeout)
        class3_rsp = Class2_3_Packet.unpack(rsp)

        if class3_rsp.data_item.type_id != CPFId.CONNECTED_DATA:
            raise Exception(
                "Unexpected CPF in SendUnitData response! " +
                "expected:{}, got:{}".format(
                    CPFId.CONNECTED_DATA,
                    class3_rsp.data_item.type_id
                    )
                )
        if class3_rsp.data_item.length != len(class3_rsp.data_item.data):
            raise Exception(
                "Unexpected data length in Connected message! " +
                "expected:{}, got:{}".format(
                    class3_rsp.data_item.length,
                    len(class3_rsp.data_item.data)
                    )
                )

        cls3_pdu = Class2_3_PDU.unpack(class3_rsp.data_item.data)

        if cls3_pdu.sequence_count != self.seq_counter:
            logger.error("Unexpected sequence counter in response! expected:{}, got:{}".format(
                self.seq_counter, cls3_pdu.sequence_count))

        mr_rsp = MessageRouterResponse.unpack(cls3_pdu.payload)

        if mr_rsp.service != (service_id | 0x80):   #TODO: correct handling?
            logger.error("Unexpected service ID in response! expected:0x{:X}, got:0x{:X}".format(
                (service_id | 0x80), mr_rsp.service)
                )

        if mr_rsp.general_status != 0:
            raise CIPError(mr_rsp.general_status, mr_rsp.extended_status)

        if rsp_dt is not None:
            return rsp_dt.unpack(mr_rsp.response_data)

        return mr_rsp.response_data

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
        self.cip_produced_connection_id = None
        self.cip_consumed_connection_id = None
        self.isconnected = False

    def __del__(self):
        if self.session:
            self.session.remove_owner(self)

    def __repr__(self):
        return "peer_ip:{}, {}".format(self.session.peer_ip, self.connection_triad)
