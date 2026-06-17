from ..rw_packet import Packet
from ..cip_types import *
from ..common     import *
from ..rw_enum import REnum
from .cip_object import *

class Object0x0063_Services(CIPServiceId):
    SET_RULES = 0x4B


class Object0x0063(CIPObjectCommon):
    class_id = 0x63
    revision = 1
    class_name = "Ingress Egress Object"
    services = Object0x0063_Services

    _class_attributes = CIPClassAttributes + (
        (8, "ingress_rules_tcp_ports_supported", BYTES),
        (9, "ingress_rules_udp_ports_supported", BYTES),
        (10, "max_buffer_size_for_rules",        UDINT),
        (11, "rules_change_count",               UDINT),
        )

    _instance_attributes = (
        (1, "ingress_rules", BYTES),
        (2, "egress_rules", BYTES),
        )

    def get_attributes_all(self, instance_id):
        gaa_attr_list = []
        if instance_id == 0:
            all_gga_attr_list = [1, 2, 3, 6, 7, 8, 9, 10, 11]
        else:
            all_gga_attr_list = [1, 2]

        return super().get_attributes_all(instance_id, all_gga_attr_list)