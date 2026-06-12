from REWire.rw_enum import EnumThatWorks
from REWire.cip_types import *

class EncapsulationStatus(EnumThatWorks):
    SUCCESS                      = 0x00
    INVALID_COMMAND              = 0x01
    INSUFFICIENT_MEMORY          = 0x02
    MALFORMED_MESSAGE            = 0x03
    INVALID_SESSION_HANDLE       = 0x64
    INVALID_LENGTH               = 0x65
    UNSUPPORTED_PROTOCOL_VERSION = 0x69
    SERVICE_NOT_ALLOWED_FOR_PORT = 0x6A

class CIP_GeneralStatusCodes(EnumThatWorks):
    SUCCESS                                 = 0X00
    COMMUNICATIONS_RELATED_PROBLEM          = 0X01
    NO_RESOURCE                             = 0X02
    INVALID_DATA                            = 0X03
    INVALID_PATH                            = 0X04
    PATH_DESTINATION_UNKNOWN                = 0X05
    INCOMPLETE_DATA                         = 0X06
    CONNECTION_LOST                         = 0X07
    SERVICE_NOT_SUPPORTED                   = 0X08
    INVALID_ATTR_VALUE                      = 0X09
    ATTR_LIST_ERR                           = 0X0A
    ALREADY_IN_MODE                         = 0X0B
    OBJ_STATE_CONFLICT                      = 0X0C
    OBJ_ALREADY_EXISTS                      = 0X0D
    ATTR_NOT_SETTABLE                       = 0X0E
    PERMISSION_DENIED                       = 0X0F
    DEV_STATE_CONFLICT                      = 0X10
    REPLYDATATOOLARGE                       = 0X11
    FRAGMENTEDPRIMITIVE                     = 0X12
    NOTENOUGHDATA                           = 0X13
    ATTRIBUTE_NOT_SUPPORTED                 = 0X14
    TOOMUCHDATA                             = 0X15
    OBJDOESNOTEXIST                         = 0X16
    INVALIDFRAGMENTAION                     = 0X17
    DATANOTSAVED                            = 0X18
    DATASTOREFAILURE                        = 0X19
    REQUESTTOOLARGE                         = 0X1A
    RESPONSETOOLARGE                        = 0X1B
    MISSINGATTRLISTDATA                     = 0X1C
    INVALIDATTRLIST                         = 0X1D
    SERVICEERROR                            = 0X1E
    VENDORSPECIFICERR                       = 0X1F
    INVALIDPARAMETER                        = 0X20
    WRITEALREADYDONE                        = 0X21
    INVALIDREPLY                            = 0X22
    BUFFEROVERFLOW                          = 0X23
    INVALIDMSGFORMAT                        = 0X24
    INVALID_KEY                             = 0X25
    INVALIDPATHSIZE                         = 0X26
    UNEXPECTEDATTR                          = 0X27
    INVALIDMEMBERID                         = 0X28
    MEMBERNOTSETTABLE                       = 0X29
    GROUP2GENFAILURE                        = 0X2A
    UNKNOWNMODBUSERR                        = 0X2B
    ATTR_NOT_GETTABLE                       = 0X2C
    INSTANCENOTDELETABLE                    = 0X2D
    SERVICE_NOT_SUPPORTED_FORSPECIFIC_PATH  = 0X2E
    FRAGMENTATION_NEEDED                    = 0x2F

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
        super(EncapsulationError, self).__init__(
            "Encapsulation request received an unexpected Status: 0x{:08X}({})".format(
            status, EncapsulationStatus.name(status)))

class CIPError(Exception):
    def __init__(self, GSC, ESC=[]):
        self.GeneralStatus = GSC
        self.ExtendedStatus = ESC
        super().__init__('CIP response status: 0x{:02X}({})-{}'.format(GSC, CIP_GeneralStatusCodes.name(GSC), ESC))