from ..rw_packet import Packet
from ..cip_types import *
from ..common     import *
from ..rw_enum import REnum
from .cip_object import *

class Object0x0004_Services(CIPServiceId):
    SET_RULES = 0x4B


class Object0x0004(CIPObjectCommon):
    class_id = 0x04
    revision = 2
    class_name = "Assembly Object"
    services = Object0x0004_Services

    _class_attributes = CIPClassAttributes

    _instance_attributes = (
        (1, "number_of_members_in_list", UINT),
        (2, "member_list",               BYTES),
        (3, "data",                      BYTES),
        (4, "size",                      UINT),
        (5, "member_list_signature",     BYTES),
        )
