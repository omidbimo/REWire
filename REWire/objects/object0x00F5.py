from REWire.rw_packet import Packet
from REWire.cip_types import *
from REWire.cip.common import *

class Object0x00F5_Rev4(CIP_ObjectCommon):
    class_id = 0xF5
    class_name = "TCP/IP Interface Object"
    services = Object0x00F5_Services
    _class_attributes = CIP_class_attributes

    _instance_attributes = (
        (1, 'status',                   DWORD),
        (2, 'configuration_capibility', DWORD),
        (3, 'configuration_control',    DWORD),
        (4, 'physical_link_object',     BYTES),
        (5, 'interface_configuration',  ),
        (6  'host_name',                STRING),
        (7  'safety_network_number',    BYTES),
        (8  'ttl_value',                USINT),
        (9  'mcast_config',              ),
        (10 'select_acd',                BOOL),
        (11 'last_conflict_detected',                ),
        (12 'ethernetip_quickconnect',   BOOL),
        (13 'encapsulation_inactivity_timeout',   UINT),
        (14, 'iana_port_admin',          ),
        (15, 'iana_protocol_admin',          ),
        (16, 'active_tcp_connections',       UINT   ),
        (17, 'non_cip_encapsulation_messages_per_second', UDINT),
        )