
from typing import Any, Optional, Tuple, Union
import time
import inspect
import random
import logging
import socket
import selectors
import threading

logger = logging.getLogger(__name__)

from . import eip_encapsulation as eip_encap
from .objects import object0x0006 as ConnMng

from .common_packet_format import (
    CPF as cpf,
    CPFId,
    SequencedAddressItem,
    ConnectedDataItem,
    )

from .rw_packet import Packet
from .cip_types import *

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

from .objects.cip_object import CIPObjectFactory as CIPObject
from .exceptions import CIPError
from .unconnected_client import UnconnectedClient
from .connected_client import ConnectionTriad

__all__ = [
        "IOClient",
        ]


class Class0_1_Packet(Packet):
    _fields = (
        ('item_count',   UINT(2)),
        ('address_item', SequencedAddressItem()),
        ('data_item',    ConnectedDataItem()),
        )


class DTLSUnconnectedPacket(Packet):
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


class IOClient:
    _io_scheduler = None

    def __init__(self,
            session: eip_encap.EncapSession,
            connection_path: PaddedEPATH, # b"\x04\x20\x04\x24\x01\x2C\x64\x2C\x65"
            transport_class=TransportClass.CLASS1,
            o2t_rpi = 1000000, # uSec resolution 1000x4 -> 4 sec
            t2o_rpi = 1000000, # uSec resolution 1000x4 -> 4 sec
            timeout_multiplier = 0, # 4x RPI: connection timeout
            o2t_size = 100,
            t2o_size = 100,
            o2t_prio = 2,
            t2o_prio = 2,
            vendor_id = 65530,
            originator_serial_number = 0xC0FFEE,
            ekey: ELECTRONIC_KEY_SEGMENT = None,
            ucmm_timeout = 5000, # milliseconds
            ):

        if isinstance(connection_path, str) or isinstance(connection_path, bytes):
            self.connection_path = PaddedEPATH.unpack(connection_path)
        else:
            self.connection_path = connection_path

        if transport_class > TransportClass.CLASS1:
            raise Exception(f"Unsupported transport class: {transport_class} for an implicit connection.")

        self.session = session
        self.target_ip = None
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
        self.transport_class = transport_class

        self._o2t_socket = None
        self._t2o_socket = None
        self._next_send = None
        self._producing_encap_seq_counter = UDINT(0)
        self._producing_data_sequence_count = UINT(0)
        self._producing_run_idle = UDINT(0)
        self._producer_data_pending = bytearray(bytes(t2o_size))
        self._producer_data = bytearray()

        self._consuming_encap_seq_counter = UDINT(0)
        self._consuming_data_sequence_count = UINT(0)
        self._consuming_run_idle = UDINT(0)
        self._consumer_data_pending = bytearray()
        self._consumer_data = bytearray()

        if self._io_scheduler is None:
            self._io_scheduler = IOScheduler()

    @property
    def rpi(self):
        return self.o2t_api

    @property
    def socket(self):
        return self._o2t_socket

    @property
    def next_send(self):
        return self._next_send

    @property
    def received_data(self):
        self._consumer_data[:] = self._consumer_data_pending
        return self._consumer_data

    def update_output(self, data:bytes, data_sequence_counter:int=None, run_idle_value:int=None):
        """
        Update the cyclic O->T process data.
        Args:
            data: I/O data payload in bytes.
            data_sequence_counter: Optional 2-byte data sequence counter. Omit if not used in the packet
            run_idle_value: Optional 32-bit Run/Idle header value. Omit if not used in the packet.

        Payload format transmitted:
            [Data Sequence Counter (0 or 2 bytes)]
            [Run/Idle Header       (0 or 4 bytes)]
            [User Data]

        The user is responsible for providing the data whose size, together with any protocol headers,
        matches the O->T connection size negotiated during the Forward Open.

        Example: negotiated O->T connection size = 100 bytes, 32-bit header format
            Class 1 payload: Sequence Counter (2) + Run/Idle (4) + User Data (94) = 100
            Class 0 payload: Run/Idle (4) + User Data (96) = 100

        No size validation or padding is performed before send.
        Incorrect data length produces an invalid cyclic I/O packet.
        """
        data_counter = BYTES()
        run_idle_header = BYTES()

        if data_sequence_counter is not None:
            data_counter = UINT(data_sequence_counter & 0xFFFF)
        if run_idle_value is not None:
            run_idle_header = UDINT(run_idle_value & 0xFFFFFFFF)

        self._producer_data_pending = bytearray(data_counter.pack() + run_idle_header.pack() + data)

    def _send(self):
        self._producer_data[:] = self._producer_data_pending
        self._producing_encap_seq_counter += 1
        o2t_packet = Class0_1_Packet()
        o2t_packet.address_item= SequencedAddressItem(connection_identifier=self.cip_producer_connection_id,
                                                      encapsulation_sequence_number=self._producing_encap_seq_counter)
        o2t_packet.data_item = ConnectedDataItem(length=len(self._producer_data), data=self._producer_data)

        self._o2t_socket.sendto(o2t_packet.pack(), (self.target_ip, 2222))

    def _receive(self):
        data, addr = self.socket.recvfrom(1500)

        t2o_packet = Class0_1_Packet.unpack(data)

        if t2o_packet.address_item.connection_identifier != self.cip_consumer_connection_id:
            raise Exception("Unexpected O->T Connection Id! Expected: " \
                f"0x{self.cip_consumer_connection_id:08X}, got: 0x{t2o_packet.address_item.connection_identifier:08X}")

        if t2o_packet.address_item.encapsulation_sequence_number != self._consuming_encap_seq_counter + 1:
            raise Exception("Unexpected O->T sequence number! Expected: "
                f"0x{self._consuming_encap_seq_counter:08X}" \
                f", got: 0x{t2o_packet.address_item.encapsulation_sequence_number:08X}")

        self._consuming_encap_seq_counter = t2o_packet.address_item.encapsulation_sequence_number
        self._consumer_data_pending = t2o_packet.data_item.data[:t2o_packet.data_item.length]
        self.isconnected = True

    def is_send_due(self, now):
        return now >= self._next_send

    def schedule_next_send(self, now):
        while self._next_send <= now:
            self._next_send += (self.o2t_api / 1000000.0)

    def start(self):
        self._next_send = time.monotonic()
        self._io_scheduler.add(self)
        self._io_scheduler.start()
        logger.info("Starting Class 1 producer/consumer - " \
            f"<O->T: 0x{self.cip_producer_connection_id:08X}, T->O: 0x{self.cip_consumer_connection_id:08X}>")

    def open(self):
        if not self.session.handle:
            self.session.open()

        self.target_ip = self.session.peer_ip

        transport_class_and_trigger = TransportClassTrigger(
                TransportClass.CLASS0 if self.transport_class==0 else TransportClass.CLASS1 ,
                ProductionTrigger.CYCLIC,
                TransportDirection.CLIENT
                )

        # 2^tick_time * timeout_ticks = timeout mS
        tick_time = 0
        while (2**tick_time)*255 < self.ucmm_timeout:
            tick_time += 1

        cm = CIPObject(UnconnectedClient(self.session), 6)

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

            rsp = cm.forward_open(
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

            rsp = cm.large_forward_open(
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
        # Unpacking the response
        o2t_api, t2o_api, connection_serial_number, o2t_network_connection_id, t2o_network_connection_id, to2_port , t2o_addr = rsp

        self.o2t_api = o2t_api
        self.t2o_api = t2o_api
        self.connection_serial_number = connection_serial_number
        self.cip_producer_connection_id = o2t_network_connection_id
        self.cip_consumer_connection_id = t2o_network_connection_id

        self._o2t_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self._o2t_socket.bind((socket.inet_ntoa(t2o_addr.to_bytes(4, "big")), 2222))
        logger.info(f"Class 1 connection{self.connection_triad} is opened.")


    def close(self):

        # 2^tick_time * timeout_ticks = timeout mS
        tick_time = 0
        while (2**tick_time)*255 < self.ucmm_timeout:
            tick_time += 1

        if not self.session.handle:
            self.session.open()

        cm = CIPObject(UnconnectedClient(self.session), 6)
        cm.forward_close(tick_time,
                         self.ucmm_timeout//(2**tick_time),
                         self.connection_serial_number,
                         self.originator_vendor_id,
                         self.originator_serial_number)

        logger.info(f"Class 1 connection{self.connection_triad} is closed.")

        self.cip_producer_connection_id = None
        self.cip_consumer_connection_id = None
        self.isconnected = False
        self.session.close()

    @property
    def connection_triad(self):
        return ConnectionTriad(
                    self.connection_serial_number,
                    self.originator_serial_number,
                    self.originator_vendor_id,
                    )


class DTLSClient(ExplicitTransport):
    def __init__(self, session):
        super().__init__()
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

        dtls_ucm = DTLSUnconnectedPacket(mr_req.pack())
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

            rsp_mr = MessageRouterResponse.unpack(dtls_ucm.unconnected_message)

            if rsp_mr.service != (service_id | 0x80):
                raise Exception("Unexpected service ID in response! expected:{}, got:{}".format(
                    (service_id | 0x80), rsp_mr.service))
            if rsp_mr.general_status != 0:
                raise CIPError(rsp_mr.general_status, rsp_mr.extended_status)

            if rsp_dt is not None:
                return rsp_dt.unpack(rsp_mr.response_data._value)

            return rsp_mr.response_data._value
        raise Exception("No response from server!")

class IOScheduler:
    """Schedules and dispatches multiple EtherNet/IP Class 1 connections."""

    def __init__(self):
        self._selector = selectors.DefaultSelector()
        self._connections = {}
        self._lock = threading.Lock()

        self._running = False
        self._thread = None

    def add(self, connection):
        """
        Register a Class1Connection.

        The connection must provide:

            _receive()
            _send()
            next_send
        """
        with self._lock:
            self._connections[connection.connection_triad] = connection
            self._selector.register(connection.socket, selectors.EVENT_READ, connection)

    def remove(self, connection):
        with self._lock:
            self._connections.pop(connection.connection_triad, None)

            try:
                self._selector.unregister(connection.socket)
            except Exception:
                pass

    def start(self):
        if self._running:
            return

        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True, name="Scheduler")
        self._thread.start()

    def stop(self):
        self._running = False

        if self._thread:
            self._thread.join()

    def _run(self):
        while self._running:

            with self._lock:
                connections = list(self._connections.values())

            if not connections:
                time.sleep(0.1)
                continue

            # Calculating the next send/receive deadline
            now = time.monotonic()
            next_deadline = min(conn.next_send for conn in connections)
            timeout = max(0.0, next_deadline - now)

            receive_events = self._selector.select(timeout)

            for event, _ in receive_events:
                connection = event.data
                connection._receive()

            now = time.monotonic()

            for connection in connections:
                if connection.is_send_due(now):
                    connection._send()
                    connection.schedule_next_send(now)
