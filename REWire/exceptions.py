from .common import CIPGeneralStatus
from .rw_enum import REnum
from .cip_types import *

class EncapsulationStatus(REnum):
    SUCCESS                      = 0x00
    INVALID_COMMAND              = 0x01
    INSUFFICIENT_MEMORY          = 0x02
    MALFORMED_MESSAGE            = 0x03
    INVALID_SESSION_HANDLE       = 0x64
    INVALID_LENGTH               = 0x65
    UNSUPPORTED_PROTOCOL_VERSION = 0x69
    SERVICE_NOT_ALLOWED_FOR_PORT = 0x6A

class ExtendedStatus(ARRAY):

    def __init__(self, items=[]):
        super().__init__(UINT, items)

    @classmethod
    def dissect(cls, bstream):
        length, bstream = USINT.dissect(bstream)
        return super().dissect(bstream, UINT, length)

    def __str__(self):
        return "["+",".join("0x{:02X}".format(err) for err in self)+"]"

class EncapsulationError(Exception):
    def __init__(self, status):
        self.status = status
        super().__init__(
            "Encapsulation request received an unexpected Status: 0x{:08X}({})".format(
            status, EncapsulationStatus.name(status)))

class CIPError(Exception):
    def __init__(self, GSC, ESC=[]):
        self.GeneralStatus = GSC
        self.ExtendedStatus = ESC
        super().__init__('CIP response status: 0x{:02X}({})-{}'.format(GSC, CIPGeneralStatus(GSC).name, ESC))