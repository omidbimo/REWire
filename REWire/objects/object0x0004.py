from REWire.rw_packet import Packet
from REWire.cip_types import *
from REWire.cip_object import *
from REWire.common     import *
from REWire.rw_enums import EnumThatWorks

class Object0x0004_Services(CIPServiceId):
    SET_RULES = 0x4B


class Object0x0004_Rev2(CIP_ObjectCommon):
    class_id = 0x04
    class_name = "Assembly Object"
    services = Object0x0004_Services

    _class_attributes = CIP_class_attributes

    _instance_attributes = (
        (1, "number_of_members_in_list", UINT),
        (2, "member_list",               BYTES),
        (3, "data",                      BYTES),
        (4, "size",                      UINT),
        (5, "member_list_signature",     BYTES),
        )
