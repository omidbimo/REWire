import logging
logger = logging.getLogger(__name__)

from ..rw_packet import Packet
from ..cip_types import *
from ..common    import *
from ..rw_enum import REnum
from ..common_packet_format import SockaddrInfoItem

from .cip_object import *
from .object0x0005_Rev2 import TransportClassTrigger


class Object0x0006_Services(CIPServiceId):
    FORWARD_CLOSE           = 0x4E
    UNCONNECTED_SEND        = 0x52
    FORWARD_OPEN            = 0x54
    GET_CONNECTION_DATA     = 0x56
    SEARCH_CONNECTION_DATA  = 0x57
    GET_CONNECTION_OWNER    = 0x5A
    LARGE_FORWARD_OPEN      = 0x5B


class Priority(REnum):
    LOW       = 0
    HIGH      = 1
    SCHEDULED = 2
    URGENT    = 3


class ConnectionType(REnum):
    NULL        = 0
    MULTICAST   = 1
    POINT2POINT = 2


class NetworkConnectionParameters:

    def __init__(self, connection_size, fixed_variable, priority, connection_type, redundant_owner, large_forward_open=False):
        self.connection_size = connection_size
        self.fixed_variable  = int(fixed_variable)
        self.priority        = priority
        self.connection_type = connection_type
        self.redundant_owner = int(redundant_owner)
        self.large_forward_open = large_forward_open

    def pack(self):
        if self.large_forward_open is True:
            return UDINT((self.connection_size & 0xFFFF) |
                        (self.fixed_variable << 25) |
                        (self.priority << 26) |
                        (self.connection_type << 29) |
                        (self.redundant_owner << 31)
                        ).pack()

        return UINT((self.connection_size & 0x1FF)  |
                    (self.fixed_variable << 9) |
                    (self.priority << 10) |
                    (self.connection_type << 13) |
                    (self.redundant_owner << 15)
                    ).pack()


class ForwardOpenRequest(Packet):
    _fields = (
        ('priority_time_tick',                  BYTE(0)),
        ('timeout_ticks',                       USINT(0)),
        ('o2t_network_connection_id',           UDINT(0)),
        ('t2o_network_connection_id',           UDINT(0)),
        ('connection_serial_number',            UINT(0)),
        ('originator_vendor_id',                UINT(0)),
        ('originator_serial_number',            UDINT(0)),
        ('connection_timeout_multiplier',       USINT(0)),
        ('reserved',                            BYTES(0, length=3)),
        ('o2t_rpi',                             UDINT(0)), # Request packet intervals in uS
        ('o2t_network_connection_parameters',   NetworkConnectionParameters(0, 0, 0, 0, 0)),
        ('t2o_rpi',                             UDINT(0)), # Request packet intervals in uS
        ('t2o_network_connection_parameters',   NetworkConnectionParameters(0, 0, 0, 0, 0)),
        ('transport_class_and_trigger',         TransportClassTrigger(0, 0, 0)),
        ('connection_path',                     PaddedEPATH()),
        )


class ForwardOpenResponse(Packet):
    _fields = (
        ('o2t_network_connection_id',   UDINT(0)),
        ('t2o_network_connection_id',   UDINT(0)),
        ('connection_serial_number',    UINT(0)),
        ('originator_vendor_id',        UINT(0)),
        ('originator_serial_number',    UDINT(0)),
        ('o2t_api',                     UDINT(0)),
        ('t2o_api',                     UDINT(0)),
        ('application_reply_size',      USINT(0)),
        ('reserved',                    USINT(0)),
        ('application_reply',           BYTES()),
        )


class UnsuccessfulForwardOpenResponse(Packet):
    _fields = ( )


class ForwardCloseConnectionPath(PaddedEPATH):
    '''
    Special handler for the Forward Close Connection Path. Unlike other PaddedEPATH
    this attribute has an extra reserved USINT between the path_size and path
    '''
    def _init__(self):
        super(ForwardCloseConnectionPath, self).__init__()

    def pack(self):
        packed = bytes()
        for segment in self:
            packed += segment.pack()
        return USINT(len(packed)//2).pack() + USINT(0).pack() + packed

    @classmethod
    def dissect(cls, bstream):
        connection_path_size, bstream = USINT.dissect(bstream)
        bstream[0] = connection_path_size
        return super.dissect(bstream)


class ForwardCloseRequest(Packet):
    _fields = (
        ('priority_time_tick',          BYTE(0)),
        ('timeout_ticks',               USINT(0)),
        ('connection_serial_number',    UINT(0)),
        ('originator_vendor_id',        UINT(0)),
        ('originator_serial_number',    UDINT(0)),
        # The PATH is an exception because it has padding between the size and path
        ('connection_path',             ForwardCloseConnectionPath()),
        )


class ForwardCloseResponse(Packet):
    _fields = (
        ('connection_serial_number',    UINT(0)),
        ('originator_vendor_id',        UINT(0)),
        ('originator_serial_number',    UDINT(0)),
        ('application_reply_size',      USINT(0)),
        ('reserved',                    USINT(0)),
        ('application_reply',           BYTES()),
        )


class ConnectionTriad(Packet):
    _fields = (
        ('connection_serial_number',    UINT(0)),
        ('originator_vendor_id',        UINT(0)),
        ('originator_serial_number',    UDINT(0)),
        )


class Object0x0006(CIPObjectCommon):
    class_id = 0x06
    revision = 3
    class_name = "Connection Manager Object"
    services = Object0x0006_Services
    _class_attributes = CIPClassAttributes

    _instance_attributes = (
        (1,  "open_requests",                           UINT),
        (2,  "open_format_rejects",                     UINT),
        (3,  "open_resource_rejects",                   UINT),
        (4,  "open_other_rejects",                      UINT),
        (5,  "close_requests",                          UINT),
        (6,  "close_format_rejects",                    UINT),
        (7,  "close_other_rejects",                     UINT),
        (8,  "connection_timeouts",                     UINT),
        (9,  "connection_entry_list",                   BYTES),
        (10, "obsolete",                                USINT),
        (11, "cpu_utilization",                         UINT),
        (12, "maxbuffsize",                             UDINT),
        (13, "bufsize_remaining",                       UDINT),
        (14, "max_connection_establishment_time",       UINT),
        (15, "i/o_packets_per_second",                  UDINT),
        (16, "percent_io_utilization",                  UINT),
        (17, "explicit_packets_per_second",             UDINT),
        (18, "missed_io_packets",                       UDINT),
        (19, "cip_io_connections",                      UDINT),
        (20, "cip_explicit_connections",                UDINT),
        (21, "concurrent_connections_protocol_version", USINT),
        (22, "concurrent_connections_branch_failure",   BOOL),
        (23, "concurrent_connections_failure_counter",  UDINT),
        (24, "concurrent_connections_packets_lost",     UDINT),
        (25, "redundant_device_id",                     BYTES),
        )

    def forward_open(self,
                     time_tick,
                     timeout_ticks,
                     o2t_network_connection_id,
                     t2o_network_connection_id,
                     connection_serial_number,
                     originator_vendor_id,
                     originator_serial_number,
                     connection_timeout_multiplier,
                     o2t_rpi,# uSec resolution
                     o2t_network_connection_parameters: NetworkConnectionParameters,
                     t2o_rpi, # uSec resolution
                     t2o_network_connection_parameters: NetworkConnectionParameters,
                     transport_class_and_trigger:       TransportClassTrigger,
                     connection_path:                   PaddedEPATH):

        fwd_open_req = ForwardOpenRequest(
            priority_time_tick = time_tick,
            timeout_ticks = timeout_ticks,
            o2t_network_connection_id = o2t_network_connection_id,
            t2o_network_connection_id = t2o_network_connection_id,
            connection_serial_number = connection_serial_number,
            originator_vendor_id = originator_vendor_id,
            originator_serial_number = originator_serial_number,
            connection_timeout_multiplier = connection_timeout_multiplier,
            o2t_network_connection_parameters = o2t_network_connection_parameters,
            o2t_rpi = o2t_rpi,
            t2o_network_connection_parameters = t2o_network_connection_parameters,
            t2o_rpi = t2o_rpi,
            transport_class_and_trigger = transport_class_and_trigger,
            connection_path = connection_path,
            )

        rsp = self.client.cip_service(self.services.FORWARD_OPEN, CIPObjectId.CONNECTION_MANAGER,
                                      instance_id=1, data=fwd_open_req, timeout=5000)
        # The response may contain only a MR response or additionally two
        # Socket Address Info items if the ForwardOpen is meant to open a Class 0/1 connection.
        t2o_port = None
        t2o_addr = None
        if isinstance(rsp, tuple):
            assert len(rsp) == 3
            fwd_open_rsp = ForwardOpenResponse.unpack(rsp[0])
            import struct
            t2o_port = struct.unpack('>H', struct.pack('=H', rsp[2].sin_port))[0]
            t2o_addr = struct.unpack('>I', struct.pack('=I', rsp[2].sin_addr))[0]
        else:
            fwd_open_rsp = ForwardOpenResponse.unpack(rsp)

        """
        take the connection IDs unconditionally from the FwdOpenResponse.
        if fwd_open_req.t2o_network_connection_id != fwd_open_rsp.t2o_network_connection_id:
            raise Exception("Invalid T->O Network Connection ID in ForwardOpen response!" +
                " expected:0x{:08X}, got:0x{:08X}".format(
                    fwd_open_req.t2o_network_connection_id, fwd_open_rsp.t2o_network_connection_id))
        """
        if connection_serial_number != fwd_open_rsp.connection_serial_number:
            raise Exception("Invalid Connection Serial Number in ForwardOpen response!" +
                " expected:0x{:08X}, got:0x{:08X}".format(
                    connection_serial_number, fwd_open_rsp.connection_serial_number))

        if originator_vendor_id != fwd_open_rsp.originator_vendor_id:
            raise Exception("Invalid Originator Vendor ID in ForwardOpen response!" +
                " expected:0x{:08X}, got:0x{:08X}".format(
                    originator_vendor_id, fwd_open_rsp.originator_vendor_id))

        if originator_serial_number != fwd_open_rsp.originator_serial_number:
            raise Exception("Invalid Originator Vendor ID in ForwardOpen response!" +
                " expected:0x{:08X}, got:0x{:08X}".format(
                    originator_serial_number, fwd_open_rsp.originator_serial_number))

        if t2o_addr is not None:
            return (fwd_open_rsp.o2t_api,
                    fwd_open_rsp.t2o_api,
                    connection_serial_number,
                    fwd_open_rsp.o2t_network_connection_id,
                    fwd_open_rsp.t2o_network_connection_id,
                    t2o_port,
                    t2o_addr)

        return (fwd_open_rsp.o2t_api,
                fwd_open_rsp.t2o_api,
                connection_serial_number,
                fwd_open_rsp.o2t_network_connection_id,
                fwd_open_rsp.t2o_network_connection_id)


    def forward_close(self,
                      time_tick,
                      timeout_ticks,
                      connection_serial_number,
                      originator_vendor_id,
                      originator_serial_number):
        try:
            self.client.peer_ip
        except:
            raise Exception("No active session to close the connection 0x{:X}!".format(
                    self.client.connection.cip_producer_connection_id))
            #logger.error("No active session to close the connection 0x{:X}!".format(
            #        self.connection.cip_producer_connection_id))

        fw_close_req = ForwardCloseRequest(
                priority_time_tick = time_tick,
                timeout_ticks = timeout_ticks,
                connection_serial_number = connection_serial_number,
                originator_vendor_id = originator_vendor_id,
                originator_serial_number = originator_serial_number,
                )

        # fw_close_req.connection_path has type of PaddedEPATH
        fw_close_req.connection_path += CLASS_ID_SEGMENT(CIPObjectId.MESSAGE_ROUTER)
        fw_close_req.connection_path += INSTANCE_ID_SEGMENT(1)

        cip_data = self.client.cip_service(self.services.FORWARD_CLOSE,
                CIPObjectId.CONNECTION_MANAGER,
                instance_id = 1,
                data = fw_close_req,
                timeout=5000,)

        fwd_close_rsp = ForwardCloseResponse().unpack(cip_data)

        if fwd_close_rsp.connection_serial_number != connection_serial_number:
            raise Exception("Invalid Connection Serial Number in ForwardClose response!" +
                " expected:0x{:08X}, got:0x{:08X}".format(
                    connection_serial_number, fwd_close_rsp.connection_serial_number))

        if fwd_close_rsp.originator_vendor_id != originator_vendor_id:
            raise Exception("Invalid originator vendor id in ForwardClose response!" +
                " expected:0x{:08X}, got:0x{:08X}".format(
                    originator_vendor_id, fwd_close_rsp.originator_vendor_id))

        if fwd_close_rsp.originator_serial_number != originator_serial_number:
            raise Exception("Invalid originator serial number in ForwardClose response!" +
                " expected:0x{:08X}, got:0x{:08X}".format(
                    originator_serial_number, fwd_close_rsp.originator_serial_number))

    def large_forward_open(self,
                     time_tick,
                     timeout_ticks,
                     o2t_network_connection_id,
                     t2o_network_connection_id,
                     connection_serial_number,
                     originator_vendor_id,
                     originator_serial_number,
                     connection_timeout_multiplier,
                     o2t_rpi,# uSec resolution
                     o2t_network_connection_parameters: NetworkConnectionParameters,
                     t2o_rpi, # uSec resolution
                     t2o_network_connection_parameters: NetworkConnectionParameters,
                     transport_class_and_trigger:       TransportClassTrigger,
                     connection_path:                   PaddedEPATH):

        fwd_open_req = ForwardOpenRequest(
            priority_time_tick = time_tick,
            timeout_ticks = timeout_ticks,
            o2t_network_connection_id = o2t_network_connection_id,
            t2o_network_connection_id = t2o_network_connection_id,
            connection_serial_number = connection_serial_number,
            originator_vendor_id = originator_vendor_id,
            originator_serial_number = originator_serial_number,
            connection_timeout_multiplier = connection_timeout_multiplier,
            o2t_network_connection_parameters = o2t_network_connection_parameters,
            o2t_rpi = o2t_rpi,
            t2o_network_connection_parameters = t2o_network_connection_parameters,
            t2o_rpi = t2o_rpi,
            transport_class_and_trigger = transport_class_and_trigger,
            connection_path = connection_path,
            )

        cip_data = self.client.cip_service(self.services.LARGE_FORWARD_OPEN,
                    CIPObjectId.CONNECTION_MANAGER, instance_id = 1,
                    data = fwd_open_req, timeout=5000)

        fwd_open_rsp = ForwardOpenResponse().unpack(cip_data)

        """
        take the connection IDs unconditionally from the FwdOpenResponse.
        if fwd_open_req.t2o_network_connection_id != fwd_open_rsp.t2o_network_connection_id:
            raise Exception("Invalid T->O Network Connection ID in ForwardOpen response!" +
                " expected:0x{:08X}, got:0x{:08X}".format(
                    fwd_open_req.t2o_network_connection_id, fwd_open_rsp.t2o_network_connection_id))
        """
        if connection_serial_number != fwd_open_rsp.connection_serial_number:
            raise Exception("Invalid Connection Serial Number in ForwardOpen response!" +
                " expected:0x{:08X}, got:0x{:08X}".format(
                    connection_serial_number, fwd_open_rsp.connection_serial_number))

        if originator_vendor_id != fwd_open_rsp.originator_vendor_id:
            raise Exception("Invalid Originator Vendor ID in ForwardOpen response!" +
                " expected:0x{:08X}, got:0x{:08X}".format(
                    originator_vendor_id, fwd_open_rsp.originator_vendor_id))

        if originator_serial_number != fwd_open_rsp.originator_serial_number:
            raise Exception("Invalid Originator Vendor ID in ForwardOpen response!" +
                " expected:0x{:08X}, got:0x{:08X}".format(
                    originator_serial_number, fwd_open_rsp.originator_serial_number))

        return fwd_open_rsp.o2t_api, fwd_open_rsp.t2o_api, connection_serial_number, fwd_open_rsp.o2t_network_connection_id, fwd_open_rsp.t2o_network_connection_id
