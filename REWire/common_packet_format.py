from REWire.rw_packet import Packet
from REWire.cip_types import *

from socket import inet_ntoa
import logging
log = logging.getLogger(__name__)

class SinZero(BYTES):
    def __init__(self, value):
        if isinstance(value, int):
            value = value.to_bytes(length=8, byteorder='little')
        super().__init__(value)

    @classmethod
    def dissect(cls, bstream):
        return super().dissect(bstream, 8)


class Revision(BYTES):
    def __init__(self, value):
        if isinstance(value, int):
            value = value.to_bytes(length=2, byteorder='little')
        super().__init__(value)

    @classmethod
    def dissect(cls, bstream):
        return super().dissect(bstream, 2)


class CPF_Item(Packet):
    @classmethod
    def dissect(cls, bstream):
        type_id, _ = UINT.dissect(bstream) # Do not update bstream
        item_type = None

        if type_id == CPF.TYPE_ID_NULL_ADDRESS:
            item_type = NullAddressItem
        elif type_id == CPF.TYPE_ID_CIP_IDENTITY:
            item_type = CIPIdentityItem
        elif type_id == CPF.TYPE_ID_CIP_SECURITY_INFORMATION:
            item_type = CIPSecurityItem
        elif type_id == CPF.TYPE_ID_ETHERNETIP_CAPABILITY:
            item_type = EtherNetIPCapabilityItem
        elif type_id == CPF.TYPE_ID_ETHERNETIP_USAGE:
            item_type = EtherNetIPUsageItem
        elif type_id == CPF.TYPE_ID_CONNECTED_ADDRESS:
            item_type = ConnectedAddressItem
        elif type_id == CPF.TYPE_ID_CONNECTED_DATA:
            item_type = ConnectedDataItem
        elif type_id == CPF.TYPE_ID_UNCONNECTED_DATA:
            item_type = UnconnectedDataItem
        elif type_id == CPF.TYPE_ID_LIST_SERVICES:
            item_type = ListServicesItem
        elif type_id == CPF.TYPE_ID_SOCKADDR_INFO_O2T:
            item_type = SockaddrInfoItem
        elif type_id == CPF.TYPE_ID_SOCKADDR_INFO_T2O:
            item_type = SockaddrInfoItem
        elif type_id == CPF.TYPE_ID_SEQUENCED_ADDRESS:
            item_type = SequencedAddressItem
        elif type_id == CPF.TYPE_ID_DTLS_UNCONNECTED_MESSAGE:
            item_type = DTLS_UnconnectedMessageItem
        else:
            raise Exception(f"Unknown CPF item: 0x{type_id:X}")
        # Don't call the item_type.dissect(). this will recall the super.dissect which is this
        # method and leads to recursion. The only way to avoid recursion is to call the CPF_Item's super
        # and pass the cls explicitly
        return super(CPF_Item, item_type).dissect(bstream)


class CPF(ARRAY):
    TYPE_ID_NULL_ADDRESS                = 0x0000
    TYPE_ID_CIP_IDENTITY                = 0x000C
    TYPE_ID_CIP_SECURITY_INFORMATION    = 0x0086
    TYPE_ID_ETHERNETIP_CAPABILITY       = 0x0087
    TYPE_ID_ETHERNETIP_USAGE            = 0x0088
    TYPE_ID_CONNECTED_ADDRESS           = 0x00A1
    TYPE_ID_CONNECTED_DATA              = 0x00B1
    TYPE_ID_UNCONNECTED_DATA            = 0x00B2
    TYPE_ID_LIST_SERVICES               = 0x0100
    TYPE_ID_SOCKADDR_INFO_O2T           = 0x8000
    TYPE_ID_SOCKADDR_INFO_T2O           = 0x8001
    TYPE_ID_SEQUENCED_ADDRESS           = 0x8002
    TYPE_ID_DTLS_UNCONNECTED_MESSAGE    = 0x8003

    def __init__(self, items=None):
        items = items or []
        super().__init__(dtype=CPF_Item, items=items)

    def pack(self):
        return UINT(len(self)).pack() + self.pack()

    @classmethod
    def unpack(cls, bstream):
        return super().unpack(bstream, CPF_Item)

    @classmethod
    def dissect(cls, bstream):
        item_count, bstream = UINT.dissect(bstream)
        return super().dissect(bstream, CPF_Item, item_count)


class NullAddressItem(CPF_Item):
    _fields = (
        ('type_id', UINT(CPF.TYPE_ID_NULL_ADDRESS)),
        ('length',  UINT(0)),
        )


class ConnectedAddressItem(CPF_Item):
    _fields = (
        ('type_id', UINT(CPF.TYPE_ID_CONNECTED_ADDRESS)),
        ('length', UINT(4)),
        ('connection_identifier', UDINT(0)),
        )


class SequencedAddressItem(CPF_Item):
    _fields = (
        ('type_id', UINT(CPF.TYPE_ID_SEQUENCED_ADDRESS)),
        ('length', UINT(0)),
        ('connection_identifier', UDINT(0)),
        ('encapsulation_sequence_number', UDINT(0)),
        )


class UnconnectedDataItem(CPF_Item):
    _fields = (
        ('type_id', UINT(CPF.TYPE_ID_UNCONNECTED_DATA)),
        ('length', UINT(0)),
        ('data', BYTES()),
        )

    def __init__(self, data=b""):
        super().__init__(length=len(data), data=data)


class ConnectedDataItem(CPF_Item):
    _fields = (
        ('type_id', UINT(CPF.TYPE_ID_CONNECTED_DATA)),
        ('length', UINT(0)),
        ('data', BYTES()),
        )

    def __init__(self, data=b""):
        super().__init__(length=len(data), data=data)


class ListServicesItem(CPF_Item):
    _fields = (
        ('type_id', UINT(CPF.TYPE_ID_LIST_SERVICES)),
        ('length', UINT(0)),
        ('protocol_version', UINT(0)),
        ('capability_flags', UINT(0)),
        ('service_name', STRING()),
        )

    def __str__(self):
        msg = "Capability Flags: 0x{:04X}\n".format(self.capability_flags)
        if self.capability_flags == 0:
            msg += "".ljust(4, ' ') + "-\n"
        if self.capability_flags & (1 << 5):
            msg += "".ljust(4, ' ') + "- Supports EtherNet/IP encapsulation of CIP\n"
        if self.capability_flags & (1 << 8):
            msg += "".ljust(4, ' ') + "- Supports CIP transport class 0 or 1 UDP-based connections\n"
        if self.capability_flags & ~((1 << 5) | (1 << 8)):
            msg += "".ljust(4, ' ') + "- Unknown capability Flags are set\n"
        msg += "Name of Service: {}".format(self.service_name)
        return msg


class SockaddrInfoItem(CPF_Item):
    _fields = (
        ('type_id', UINT(0)),
        ('length', UINT(0)),
        ('sin_family', INT(0)),
        ('sin_port', UINT(0)),
        ('sin_addr', UDINT(0)),
        ('sin_zero', BYTES(8)),
        )


class CIPIdentityItem(CPF_Item):
    _fields = (
        ('type_id', UINT(CPF.TYPE_ID_CIP_IDENTITY)),
        ('length', UINT(0)),
        ('encapsulation_protocol_version', UINT(0)),
        ('sin_family', INT(0)),
        ('sin_port', UINT(0)),
        ('sin_addr', UDINT(0)),
        ('sin_zero', SinZero(0)),
        ('vendor_id', UINT(0)),
        ('device_type', UINT(0)),
        ('product_code', UINT(0)),
        ('revision', Revision(0)),
        ('status', WORD(0)),
        ('serial_number', UDINT(0)),
        ('product_name', SHORT_STRING()),
        ('state', USINT(0)),
        )

    def __str__(self):
        return (
            "EncapProtocolVersion: {}\n".format(self.encapsulation_protocol_version) +
            "sin_family:           {}\n".format(self.sin_family) +
            "sin_port:             {}(0x{:X})\n".format(self.sin_port, self.sin_port) +
            "sin_addr:             {}\n".format(inet_ntoa(self.sin_addr.pack())) +
            "sin_Zero:             {}\n".format(":".join("{:02X}".format(octet) for octet in self.sin_zero)) +
            "vendor_id:            {}(0x{:X})\n".format(self.vendor_id, self.vendor_id) +
            "device_type:          {}(0x{:X})\n".format(self.device_type, self.device_type) +
            "product_code:         {}(0x{:X})\n".format(self.product_code, self.product_code) +
            "revision:             {}.{}\n".format(self.revision[0], self.revision[1]) +
            "status:               {}(0x{:X})\n".format(self.status, self.status) +
            "serial_number:        {}\n".format(self.serial_number) +
            "product_name:         {}\n".format(self.product_name) +
            "state:                {}(0x{:X})".format(self.state, self.state)
            )


class CIPSecurityItem(CPF_Item):
    _fields = (
                ('type_id',                     UINT(CPF.TYPE_ID_CIP_SECURITY_INFORMATION)),
                ('length',                      UINT(0)),
                ('security_profiles',           WORD(0)),
                ('cip_security_state',          USINT(0)),
                ('ethernetip_security_state',   USINT(0)),
                ('iana_port_state',             BYTE(0)),
                ('security_profile_configured', WORD(0)),
                )

    def __str__(self):
        msg = "::ListIdentity Extension 0x01 <CIP security information>\n"
        cip_security_state_msg = [
                                "Factory Default Configuration",
                                "Configuration In Progress",
                                "Configured",
                                "Incomplete Configuration",
                                ]

        eip_security_state_msg = [
                                "Factory Default Configuration",
                                "Configuration In Progress",
                                "Configured",
                                "Pull Model In Progress",
                                "Pull Model Completed",
                                "Pull Model Disabled",
                                ]

        msg += f"  Security Profiles: 0x{self.security_profiles:04X}\n"

        if self.security_profiles & (1 << 0):
            msg += "    - EtherNet/IP Integrity Profile(Obsoleted)\n"
        if self.security_profiles & (1 << 1):
            msg += "    - EtherNet/IP Confidentiality Profile\n"
        if self.security_profiles & (1 << 2):
            msg += "    - CIP Authorization Profile(Reserved)\n"
        if self.security_profiles & (1 << 3):
            msg += "    - CIP User Authentication Profile\n"

        if self.cip_security_state < len(cip_security_state_msg):
            msg += f"  CIP Security State: {self.cip_security_state} "
            msg += f"({cip_security_state_msg[self.cip_security_state]})\n"
        else:
            msg += f"  CIP Security State: {self.cip_security_state}\n"

        if self.ethernetip_security_state < len(eip_security_state_msg):
            msg += f"  EtherNet/IP Security State: {self.ethernetip_security_state} "
            msg += f"({eip_security_state_msg[self.ethernetip_security_state]})\n"
        else:
            msg += f"  EtherNet/IP Security State: {self.ethernetip_security_state}\n"

        msg += "  IANA Port State: 0x{self.iana_port_state:02X}\n"
        if self.iana_port_state & (1 << 0):
            msg += "    - 44818/tcp   Open\n"
        if self.iana_port_state & (1 << 1):
            msg += "    - 44818/udp   Open\n"
        if self.iana_port_state & (1 << 2):
            msg += "    - 2222/udp    Open\n"
        if self.iana_port_state & (1 << 3):
            msg += "    - 2221/tcp    Open\n"
        if self.iana_port_state & (1 << 4):
            msg += "    - 2221/udp    Open\n"

        if self.security_profile_configured == 0x00:
            msg += "  Security Profiles Configured: 0x{:04X}(None)".format(
                self.security_profile_configured)
        else:
            msg += "  Security Profiles Configured: 0x{:04X}".format(
                self.security_profile_configured)
        if self.security_profile_configured & (1 << 0):
            msg += "    - EtherNet/IP Integrity Profile(Obsoleted)"
        if self.security_profile_configured & (1 << 1):
            msg += "    - EtherNet/IP Confidentiality Profile"
        if self.security_profile_configured & (1 << 2):
            msg += "    - CIP Authorization Profile(Reserved)"
        if self.security_profile_configured & (1 << 3):
            msg += "    - CIP User Authentication Profile"
        return msg

class EtherNetIPCapabilityItem(CPF_Item):
    _fields = (
                ('type_id',                         UINT(CPF.TYPE_ID_ETHERNETIP_CAPABILITY)),
                ('length',                          UINT(0)),
                ('transport_application_profile',   DWORD(0)),
                )

    def __str__(self):
        msg = "::ListIdentity Extension 0x02 <EtherNet/IP Transports>\n"
        msg += f"  EtherNet/IP Capability: 0x{self.transport_application_profile:08X}\n"
        if self.transport_application_profile & (1 << 0):
            msg += "    - bit0: UCMM over TCP\n"
        if self.transport_application_profile & (1 << 1):
            msg += "    - bit1: UCMM over UDP\n"
        if self.transport_application_profile & (1 << 2):
            msg += "    - bit2: Class3 connections via TCP\n"
        if self.transport_application_profile & (1 << 3):
            msg += "    - bit3: Class3 connections via UDP\n"
        if self.transport_application_profile & (1 << 4):
            msg += "    - bit4: Class2 connections via TCP\n"
        if self.transport_application_profile & (1 << 5):
            msg += "    - bit5: Class2 connections via UDP\n"
        if self.transport_application_profile & (1 << 6):
            msg += "    - bit6: Class1 connections\n"
        if self.transport_application_profile & (1 << 7):
            msg += "    - bit7: Class0 connections"
        return msg


class EtherNetIPUsageItem(CPF_Item):
    _fields = (
                ('type_id',                     UINT(CPF.TYPE_ID_ETHERNETIP_USAGE)),
                ('length',                      UINT(0)),
                ('usage_application_profile',   DWORD(0)),
                )

    def __str__(self):
        msg = "::ListIdentity Extension 0x03 <EtherNet/IP Usage>\n"
        msg += f"  EtherNet/IP Usage: 0x{self.usage_application_profile:08X}\n"
        if self.usage_application_profile & (1 << 0):
            msg += "    - bit0: Standard EtherNet/IP usage profile\n"
        if self.usage_application_profile & (1 << 1):
            msg += "    - bit1: In-Cabinet EtherNet/IP usage profile"
        return msg


class DTLS_UnconnectedMessageItem(CPF_Item):
    _fields = (
        ('type_id', UINT(CPF.TYPE_ID_DTLS_UNCONNECTED_MESSAGE)),
        ('length', UINT(10)),
        ('unconn_msg_type', UINT(1)),
        ('transaction_number', UDINT(0)),
        ('status', UDINT(0)),
        ('unconnected_message', BYTES()),
        )

    def __init__(self, unconnected_message=b""):
        super().__init__(length=10+len(unconnected_message), unconnected_message=unconnected_message)

