from time import sleep
from typing import Any, Optional, Tuple, Union
import inspect
import random
import logging

from . import eip_encapsulation as eip_encap
from .objects import object0x0006 as ConnMng

from .common_packet_format import (
    CPF as cpf,
    SequencedAddressItem,
    ConnectedDataItem,
    )

from .rw_packet import Packet
from .cip_types import *
from .utils import *
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
from .unconnected_client import UnconnectedClient
from .cip_objects import *


logger = logging.getLogger(__name__)

__all__ = [
        "IOClient",
        ]

class Class3PDU(Packet):
    _fields = (
        ("sequence_count", UINT(0)),
        ("payload", BYTES()),
        )


class Class0_1_Packet(Packet):
    _fields = (
                ('item_count',   UINT(2)),
                ('address_item', SequencedAddressItem()),
                ('data_item',    ConnectedDataItem()),
                )


class IOClient:
    def __init__(self,
            unconnected_client,
            connection_path, # b"\x04\x20\x04\x24\x01\x2C\x64\x2C\x65"
            o2t_rpi = 1000000, # uSec resolution 1000x4 -> 4 sec
            t2o_rpi = 1000000, # uSec resolution 1000x4 -> 4 sec
            timeout_multiplier = 0, # 4x RPI: connection timeout
            o2t_size = 100,
            t2o_size = 100,
            o2t_prio = 2,
            t2o_prio = 2,
            vendor_id = 0,
            originator_serial_number = 0xC0FFEE,
            ekey: ELECTRONIC_KEY_SEGMENT = None,
            ucmm_timeout = 5000, # milliseconds
            ):

        self.ucc = unconnected_client
        if isinstance(connection_path, str) or isinstance(connection_path, bytes):
            self.connection_path = EPATH(padded=True, path=connection_path)
        else:
            self.connection_path = connection_path

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
        self.session = None

    def connect(self):
        transport_class_and_trigger = TransportClassTrigger(
                TransportClass.CLASS1,
                ProductionTrigger.CYCLIC,
                TransportDirection.CLIENT
                )

        # 2^tick_time * timeout_ticks = timeout mS
        tick_time = 0
        while (2**tick_time)*255 < self.ucmm_timeout:
            tick_time += 1


        #self.ucc.open()

        if isinstance(self.ucc, UnconnectedClient):
            self.session = self.ucc.session
        else:
            self.session = self.ucc

        cm = CIP_Object(self.ucc, 6)

        if self.o2t_size <= 511 and self.t2o_size <= 511:
            o2t_conn_params = ConnMng.NetworkConnectionParameters(
                connection_size = self.o2t_size,
                fixed_variable  = True,
                priority        = ConnMng.Priority.LOW,
                connection_type = ConnMng.ConnectionType.POINT2POINT,
                redundant_owner = False,
                )

            t2o_conn_params = ConnMng.NetworkConnectionParameters(
                connection_size = self.t2o_size,
                fixed_variable  = True,
                priority        = ConnMng.Priority.LOW,
                connection_type = ConnMng.ConnectionType.POINT2POINT,
                redundant_owner = False,
                )

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
                        connection_path = self.connection_path,
                        )
        else:
            o2t_conn_params = ConnMng.NetworkConnectionParameters(
                connection_size = self.o2t_size,
                fixed_variable  = True,
                priority        = ConnMng.Priority.LOW,
                connection_type = ConnMng.ConnectionType.POINT2POINT,
                redundant_owner = False,
                large_forward_open=True,
                )

            t2o_conn_params = ConnMng.NetworkConnectionParameters(
                connection_size = self.t2o_size,
                fixed_variable  = True,
                priority        = ConnMng.Priority.LOW,
                connection_type = ConnMng.ConnectionType.POINT2POINT,
                redundant_owner = False,
                large_forward_open=True,
                )

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
                        connection_path = self.connection_path,
                        )

        self.connection_serial_number = connection_serial_number
        self.cip_produced_connection_id = o2t_network_connection_id
        self.cip_consumed_connection_id = t2o_network_connection_id

        self.session.connections.append(self)
        self.isconnected = True
        logger.debug("Class 3 connection id:0x{:X} is established.".format(o2t_network_connection_id))

    def disconnect(self):
        """
        try:
            self.session.peer_ip
        except:
            raise Exception("No active session to close the connection 0x{:X}!".format(
                    self.cip_produced_connection_id))
            #logger.error("No active session to close the connection 0x{:X}!".format(
            #        self.connection.cip_produced_connection_id))
        """
        # 2^tick_time * timeout_ticks = timeout mS
        tick_time = 0
        while (2**tick_time)*255 < self.ucmm_timeout:
            tick_time += 1

        cm = CIP_Object(self.ucc, 6)
        cm.forward_close(tick_time,
                         self.ucmm_timeout//(2**tick_time),
                         self.connection_serial_number,
                         self.originator_vendor_id,
                         self.originator_serial_number)

        logger.debug("Class 3 connection id:0x{:08X} is closed.".format(
                self.cip_produced_connection_id))

        self.cip_produced_connection_id = None
        self.cip_consumed_connection_id = None
        self.isconnected = False
        self.session = None
        self.ucc = None

    @property
    def triad(self):
        return (self.connection_serial_number,
                self.originator_vendor_id,
                self.originator_serial_number)