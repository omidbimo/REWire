from time import time, sleep, asctime
from typing import Literal, Tuple, Annotated
import random
import logging

from .rw_enum import REnum
from .rw_packet import Packet
from .cip_types import *
from .rw_socket import RWSocket, RW_TCPSocket, RW_TLSSocket, TCP, UDP
from .exceptions import EncapsulationStatus, EncapsulationError
from .rw_watchdog import WatchdogTimer
from .common_packet_format import (
    CPF,
    CPFId,
    ConnectedAddressItem,
    ConnectedDataItem,
    NullAddressItem,
    UnconnectedDataItem,
    )

logger = logging.getLogger(__name__)

class EncapsulationCommands(REnum):
    NOP                 = 0x00
    LIST_SERVICES       = 0x04
    LIST_IDENTITY       = 0x63
    LIST_INTERFACES     = 0x64
    REGISTER_SESSION    = 0x65
    UNREGISTER_SESSION  = 0x66
    SEND_RR_DATA        = 0x6F
    SEND_UNIT_DATA      = 0x70
    START_DTLS          = 0xC8


class SenderContext(BYTES):
    def __init__(self, value):
        if isinstance(value, int):
            value = value.to_bytes(length=8, byteorder='little')
        super().__init__(value)

    @classmethod
    def dissect(cls, bstream):
        return super().dissect(bstream, 8)


class EncapsulationHeader(Packet):
    _fields = (
        ("command",         UINT(0)),
        ("length",          UINT(0)),
        ("session_handle",  UDINT(0)),
        ("status",          UDINT(0)),
        ("sender_context",  SenderContext(0)),
        ("options",         UDINT(0)),
        )


class EncapsulationPacket(Packet):
    _fields = (
        ('encap_header', EncapsulationHeader()),
        ("encap_data",   SenderContext(0)),
        )


class NOP(Packet):
    _fields = (
        ("command",             UINT(EncapsulationCommands.NOP)),
        ("length",              UINT(0)),
        ("session_handle",      UDINT(0)),
        ("status",              UDINT(0)),
        ("sender_context",      SenderContext(0)),
        ("options",             UDINT(0)),
        )


class ListServicesRequest(Packet):
    _fields = (
        ("command",             UINT(EncapsulationCommands.LIST_SERVICES)),
        ("length",              UINT(0)),
        ("session_handle",      UDINT(0)),
        ("status",              UDINT(0)),
        ("sender_context",      SenderContext(0)),
        ("options",             UDINT(0)),
        )


class ListServicesResponse(Packet):
    _fields = (
        ("command",             UINT(0)),
        ("length",              UINT(0)),
        ("session_handle",      UDINT(0)),
        ("status",              UDINT(0)),
        ("sender_context",      SenderContext(0)),
        ("options",             UDINT(0)),
        ('encap_data',          BYTES()),
        )


class ListIdentityRequest(Packet):
    _fields = (
        ("command",             UINT(EncapsulationCommands.LIST_IDENTITY)),
        ("length",              UINT(0)),
        ("session_handle",      UDINT(0)),
        ("status",              UDINT(0)),
        ("sender_context",      SenderContext(0)),
        ("options",             UDINT(0)),
        )

    def __init__(self, max_delay_ms=500):
        super().__init__(sender_context=SenderContext(max_delay_ms))


class ListIdentityResponse(Packet):
    _fields = (
        ("command",             UINT(0)),
        ("length",              UINT(0)),
        ("session_handle",      UDINT(0)),
        ("status",              UDINT(0)),
        ("sender_context",      SenderContext(0)),
        ("options",             UDINT(0)),
        ('encap_data',          BYTES()),
        )


class ListInterfacesRequest(Packet):
    _fields = (
        ("command",             UINT(EncapsulationCommands.LIST_INTERFACES)),
        ("length",              UINT(0)),
        ("session_handle",      UDINT(0)),
        ("status",              UDINT(0)),
        ("sender_context",      SenderContext(0)),
        ("options",             UDINT(0)),
        )


class ListInterfacesResponse(Packet):
    _fields = (
        ("command",             UINT(0)),
        ("length",              UINT(0)),
        ("session_handle",      UDINT(0)),
        ("status",              UDINT(0)),
        ("sender_context",      SenderContext(0)),
        ("options",             UDINT(0)),
        ('encap_data',          BYTES()),
        )


class RegisterSessionRequest(Packet):
    _fields = (
        ("command",             UINT(EncapsulationCommands.REGISTER_SESSION)),
        ("length",              UINT(4)),
        ("session_handle",      UDINT(0)),
        ("status",              UDINT(0)),
        ("sender_context",      SenderContext(0)),
        ("options",             UDINT(0)),
        ("protocol_version",    UINT(1)),
        ("option_flags",        UINT(0)),
        )

    def __init__(self, sender_context=0):
        super().__init__(sender_context=SenderContext(sender_context))


class RegisterSessionResponse(Packet):
    _fields = (
        ("command",             UINT(0)),
        ("length",              UINT(0)),
        ("session_handle",      UDINT(0)),
        ("status",              UDINT(0)),
        ("sender_context",      SenderContext(0)),
        ("options",             UDINT(0)),
        ('protocol_version',    UINT(0)),
        ('option_flags',        UINT(0)),
        )


class UnregisterSessionRequest(Packet):
    _fields = (
        ("command",             UINT(EncapsulationCommands.UNREGISTER_SESSION)),
        ("length",              UINT(0)),
        ("session_handle",      UDINT(0)),
        ("status",              UDINT(0)),
        ("sender_context",      SenderContext(0)),
        ("options",             UDINT(0)),
        )

    def __init__(self, session_handle):
        super().__init__(session_handle=session_handle)

class SendRRData(Packet):
    _fields = (
        ("command",             UINT(EncapsulationCommands.SEND_RR_DATA)),
        ("length",              UINT(6)),
        ("session_handle",      UDINT(0)),
        ("status",              UDINT(0)),
        ("sender_context",      SenderContext(0)),
        ("options",             UDINT(0)),
        ("interface_handle",    UDINT(0)), # Shall be zero when encapsulating CIP
        ("timeout",             UINT(0)),
        ("encapsulated_packet", BYTES()),
        )


class SendUnitData(Packet):
    _fields = (
        ("command",             UINT(EncapsulationCommands.SEND_UNIT_DATA)),
        ("length",              UINT(16)),
        ("session_handle",      UDINT(0)),
        ("status",              UDINT(0)),
        ("sender_context",      SenderContext(0)),
        ("options",             UDINT(0)),
        ("interface_handle",    UDINT(0)),
        ("timeout",             UINT(0)),
        ("encapsulated_packet", BYTES()),
        )


class EncapSession():
    def __init__(self, socket_: RWSocket, timeout: float=120.0):
        self.handle = None
        self.seq_number = 0 # handle << 32
        self._owners = [] # Connections using this session
        self.inactivity_timeout = timeout
        self.watchdog = None

        if not isinstance(socket_, RW_TCPSocket) and not isinstance(socket_, RW_TLSSocket):
            raise Exception(f"Invalid socket of type {type(socket_)}! A socket of type TCP or TLS is required.")

        self.socket = socket_

    @classmethod
    def from_addr(cls, host_ip: str, server_ip: str, **kwargs):
        timeout = 120.0
        if kwargs:
            timeout = kwargs.get("timeout", 120.0)
        return cls(TCP(host_ip, server_ip), timeout)

    def open(self):
        if self.peer_ip is None:
            self.socket.connect()

        if self.handle is None:
            self.handle = register_session(self.socket)
            self.seq_number = self.handle << 32
            self.watchdog = WatchdogTimer(timeout=self.inactivity_timeout, on_timeout=self.handle_timeout)
            self.socket._sessions.append(self)

    def close(self):
        if self.peer_ip:
            if not self._owners:
                try:
                    unregister_session(self.socket, self.handle)
                except:
                    pass
                self.watchdog.stop()
                self.socket._sessions.remove(self)

                if not self.socket._sessions:
                    self.socket.close()

                self.handle = None
                self.watchdog = None
                self.seq_number = 0

    def __del__(self):
        self.close()

    @property
    def host_port(self):
        try:
            return self.socket.host_port
        except:
            return None

    @property
    def peer_ip(self):
        try:
            return self.socket.peer_ip
        except:
            return None

    @property
    def peer_port(self):
        return self.socket.peer_port

    @property
    def peer_certs(self):
        return self.socket.peer_certs

    def __repr__(self):
        return f"{self.__class__.__name__}(handle=0x{self.handle:X}, sequence_number=0x{self.seq_number:X})"

    def add_owner(self, owner):
        self._owners.append(owner)

    def remove_owner(self, owner):
        try:
            self._owners.remove(owner)
        except:
            pass

    def handle_timeout(self):
        logger.error(f"Inactivity Timeout! Session 0x{self.handle:X} closed.")
        self.close()

    """
    EncapsulationTransport contains all services required to transport
    EtherNet/IP messages.
    The following is a list of services required by the Full EtherNet/IP
    Transport profile.

    ID        Command                 Transport Protocol    session
    -----------------------------------------------------------------
    0x0000    NOP                     TCP[TLS]                 -
    0x0004    ListServices            TCP[TLS]/UDP             -
    0x0063    ListIdentity            TCP[TLS]/UDP             -
    0x0064    ListInterfaces          TCP[TLS]/UDP             -
    0x0065    RegisterSession         TCP[TLS]                 -
    0x0066    UnRegisterSession       TCP[TLS]                 -
    0x006F    SendRRData              TCP[TLS]              required
    0x0070    SendUnitData            TCP[TLS]              required
    """

def reset_encapsulation_inactivity(socket_: RWSocket):
    # Reset the encapsulation session inactivity timeout

    try:
        for session in socket_._sessions:
            session.watchdog.reset()
    except:
        pass

def nop(socket_: RWSocket) -> None:
    """
    Send the encapsulation command 0x0000 (NOP) to a remote device
    """
    reset_encapsulation_inactivity(socket_)
    req = NOP().pack()
    socket_.send(req)


def list_services_unpack_response(rsp_data, time_ref):
    services = []
    for data, sender_addr, timestamp in rsp_data:

        encap_rsp = ListServicesResponse.unpack(data)

        if encap_rsp.command != EncapsulationCommands.LIST_SERVICES:
            logger.warning("Unexpected response to List Services request!" +
                " expected:0x{:02X}, got:0x{:02X}".format(
                EncapsulationCommands.LIST_SERVICES, encap_rsp.command))
            continue

        # There might be several encap_data from multiple devices.
        logger.debug("Received ListServices from {} with {:04.3f} sec delay.".format(
            sender_addr, timestamp - time_ref))

        cpf = CPF.unpack(encap_rsp.encap_data)

        if len(cpf) > 1:
            logger.warning("Unexpected number of items ({}) in List Services response.".format(len(cpf)))

        for item in cpf:
            if item.type_id == CPFId.LIST_SERVICES:
                services.append((item, sender_addr, timestamp - time_ref))
                continue

            # Unexpected CPF item! Ignore the item.
            logger.error("Invalid item in CPF packet!" +
                "0x{:02X}".format(item.type_id))
    return services


def list_services(socket_: RWSocket):
    reset_encapsulation_inactivity(socket_)
    req = ListServicesRequest(sender_context=SenderContext(500)).pack()

    socket_.send(req)
    t_send = time()
    network_rsp = socket_.receive(1.0)

    return list_services_unpack_response(network_rsp, time_ref=t_send)


def list_identity_unpack_response(rsp_data, time_ref):
    """ Unpacks responses to a ListIdentity request.
        param: bytes rsp_data: list of network responses in format of
            [(data, sender_addr, timestamp),...]
        param: time_ref: a time reference to calculate the response delay of
               each server.
        return: A list of tuples where each tuple holds the information of one device
            [(ListIdentity_response, sender_addr(ip, port), response_delay(in seconds)), ...]
    """
    discovered = []
    for data, sender_addr, timestamp in rsp_data:

        encap_rsp = ListIdentityResponse.unpack(data)

        if encap_rsp.command != EncapsulationCommands.LIST_IDENTITY:
            logger.warning("Unexpected response to List Identity request!" +
                " expected:0x{:02X}, got:0x{:02X}".format(
                    EncapsulationCommands.LIST_IDENTITY, encap_rsp.command))

            if encap_rsp.status != 0x0000:
                raise EncapsulationError(encap_rsp.status)
            continue

        logger.debug("Received ListIdentity from {} with {:04.3f} sec delay.".format(
            sender_addr, timestamp - time_ref))

        # There might be several encap_data from multiple devices.
        # Each Encapsulated data also possibly consists of multiple CPF items.
        cpf = CPF.unpack(encap_rsp.encap_data)

        identity_items = []
        for item in cpf:
            if (item.type_id == CPFId.CIP_IDENTITY or
                item.type_id == CPFId.CIP_SECURITY_INFORMATION or
                item.type_id == CPFId.ETHERNETIP_CAPABILITY or
                item.type_id == CPFId.ETHERNETIP_USAGE):

                identity_items.append(item)
                continue

            # Unexpected CPF item! Ignore the item.
            logger.error("Invalid item in CPF packet!" +
                "0x{:02X}".format(item.type_id))

        discovered.append({"address":sender_addr, "cpf_items":identity_items, "delay":timestamp - time_ref})
    return discovered


def list_identity(socket_: RWSocket, max_delay_ms=500):
    """
    Performs a send/receive cycle for the encapsulation command: 0x0063 (ListIdentity)
    over UDP and supports both unicast and broadcast

    param: str host_ip: IPv4 of the local host in dotted-decimal format
    param: str server_ip: IPv4 of the remote server in dotted-decimal format
    param: broadcast: If True, the UDP packet will be sent as a Broadcast packet.
           In this case, the server_ip will be used as the broadcast IP
    param: max_delay_ms: Only for broadcast requests, determines the maximum
           acceptable response delay. Note that this value may be adjusted by
           the scanner to match the requirements.

    return: A list of dict objects containing the sender address info, response delay and a list of CPF items
        [{"address": sender_addr(ip, port), "cpf_items": [ListIdentity items], "delay":response_delay}, ...]

    Note: A list identity response may consist of several items:
        Identity_item, Security_item, ...
        see the common_packet_format module for more information on related item structures.
    """
    reset_encapsulation_inactivity(socket_)

    # Adjusting the delay value with respect to the CIP spec.
    try:
        if socket_.is_broadcast:
            if max_delay_ms == 0:
                max_delay_ms = 2000
            elif max_delay_ms < 500:
                max_delay_ms = 500
    except:
        pass

    req = ListIdentityRequest(max_delay_ms).pack()

    socket_.send(req)
    t_send = time()
    network_rsp = socket_.receive(float(max_delay_ms)/1000)
    return list_identity_unpack_response(network_rsp, t_send)


def list_interfaces(socket_: RWSocket):
    reset_encapsulation_inactivity(socket_)
    req = ListInterfacesRequest(sender_context=SenderContext(500)).pack()

    socket_.send(req)
    t_send = time()
    return socket_.receive(1.0) #TODO: list interfaces response


def register_session_unpack_response(rsp_data, req_sender_context):
    for data, _, timestamp in rsp_data:

        encap_rsp = RegisterSessionResponse.unpack(data)

        if encap_rsp.command != EncapsulationCommands.REGISTER_SESSION:
            logger.warning("Unexpected command in response to RegisterSession request! " +
                " expected:0x{:02X}, got:0x{:02X}".format(
                EncapsulationCommands.REGISTER_SESSION, encap_rsp.command))
            continue

        if encap_rsp.status != EncapsulationStatus.SUCCESS:
            raise EncapsulationError(encap_rsp.status)

        if encap_rsp.sender_context != req_sender_context:
            logger.warning("Unexpected sender context in response to RegisterSession request! " +
                " expected:0x{:08X}, got:0x{:08X}".format(
                req_sender_context, encap_rsp.sender_context))
            continue

        if encap_rsp.protocol_version != 1 and encap_rsp.option_flags != 0:
            raise Exception("Unexpected register session response data! " +
                "protocol version={}, option flags={}".format(
                    encap_rsp.protocol_version, encap_rsp.option_flags))
        return encap_rsp.session_handle

    raise Exception(
        "Failed to register session! No proper response from the remote server!")


def register_session(socket_: RWSocket):
    reset_encapsulation_inactivity(socket_)
    req = RegisterSessionRequest(sender_context=random.randint(0, 0xFFFFFFFFFFFFFFFF))

    socket_.send(req.pack())
    network_rsp = socket_.receive(1.0)
    session_handle = register_session_unpack_response(network_rsp, req.sender_context)
    logger.info(f"Session 0x{session_handle:08X} opened.")
    return session_handle


def unregister_session(socket_, session_handle):
    req = UnregisterSessionRequest(session_handle=session_handle,)
    socket_.send(req.pack())
    logger.info(f"Session 0x{session_handle:08X} closed.")


def send_rr_data(socket_: RWSocket, session_handle, sender_context, payload, timeout=0):
    """
    Sends the encapsulation command 0x006F(SendRRData) to a remote device
    - Only TCP-based transport is supported

    param: sock : REW_SocketWrapper
    param: session_handle
    param: payload
    param: timeout  note: When encpsulating CIP, the timeout shall be zero
    param: sender_context

    return: -
    """
    reset_encapsulation_inactivity(socket_)
    req = SendRRData(session_handle=session_handle,
                     sender_context=SenderContext(sender_context),
                     timeout=timeout,
                     encapsulated_packet=payload,
                     length=UINT(len(payload))+6,
                     )

    socket_.send(req.pack())

def rcv_rr_data(socket_: RWSocket, sender_context, timeout=5000):
    network_rsp = socket_.receive(float(timeout)/1000)

    for data, _, timestamp in network_rsp:

        encap_rsp = SendRRData.unpack(data)

        if encap_rsp.command != EncapsulationCommands.SEND_RR_DATA:
            logger.warning("Unexpected response to SendRRData request!" +
                " expected:0x{:02X}, got:0x{:02X}".format(EncapsulationCommands.SEND_RR_DATA, encap_rsp.command))
            continue

        if encap_rsp.status != EncapsulationStatus.SUCCESS:
            raise EncapsulationError(encap_rsp.status)

        if encap_rsp.sender_context != SenderContext(sender_context):
            raise Exception("Unexpected encap sender_context in SendRRData response! " +
                            f"expected:{sender_context}, got={encap_rsp.sender_context}")

        if encap_rsp.interface_handle != 0:
            logger.error("Unexpected interface handle in response to SendRRData request!" +
                f" expected:0x{encap_rsp.interface_handle:08X}, got:0x{0:08X}")

        reset_encapsulation_inactivity(socket_)
        return (encap_rsp.encapsulated_packet, timestamp)

    raise Exception(
        "SendRRData failed! No proper response from the remote server within {:.3f} seconds!".format(timeout))


def send_unit_data(socket_: RWSocket, session_handle, sender_context, payload, timeout=0):
    reset_encapsulation_inactivity(socket_)
    req = SendUnitData( session_handle=session_handle,
                        sender_context=SenderContext(sender_context),
                        timeout=UINT(timeout),
                        encapsulated_packet=payload,
                        length=UINT(len(payload))+6,
                        )

    socket_.send(req.pack())

def rcv_unit_data(socket_, sender_context, timeout=5000):
    network_rsp = socket_.receive(float(timeout)/1000)

    for data, _, timestamp in network_rsp:

        encap_rsp = SendUnitData.unpack(data)

        if encap_rsp.command != EncapsulationCommands.SEND_UNIT_DATA:
            logger.warning("Unexpected response to SendUnitData request!" +
                " expected:0x{:02X}, got:0x{:02X}".format(EncapsulationCommands.SEND_UNIT_DATA, encap_rsp.command))
            continue

        if encap_rsp.status != EncapsulationStatus.SUCCESS:
            raise EncapsulationError(encap_rsp.status)

        if encap_rsp.interface_handle != 0:
            logger.error("Unexpected interface handle in response to SendUnitData request!" +
                         f" expected:0x{encap_rsp.interface_handle:08X}, got:0x{0:08X}")

        reset_encapsulation_inactivity(socket_)
        return (encap_rsp.encapsulated_packet, timestamp)

    raise Exception(f"SendUnitData failed! Received no response from the remote server: {socket_.peer_ip}")
