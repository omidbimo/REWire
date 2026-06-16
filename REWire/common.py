from REWire.rw_packet import Packet
from REWire.cip_types import *
from REWire.rw_enum import REnum

"""
__all__ = [
    "CIPObjectId",
    "CIPServiceId",

    ]
"""
class CIPGeneralStatus(REnum):
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


class CIPObjectId(REnum):
    IDENTITY                    = 0X01
    MESSAGE_ROUTER              = 0X02
    DEVICENET                   = 0X03
    ASSEMBLY                    = 0X04
    CONNECTION                  = 0X05
    CONNECTION_MANAGER          = 0X06
    REGITER                     = 0X07
    DISCRETE_INPUT_POINT        = 0X08
    DISCRETE_OUTPUT_POINT       = 0X09
    ANALOG_INPUT_POINT          = 0X0A
    ANALOG_OUTPUT_POINT         = 0X0B
    PRESENCE_SENSING            = 0X0E
    PARAMETER                   = 0X0F
    PARAMETER_GROUP             = 0X10
    GROUP                       = 0X12
    DISCRETE_INPUT_GROUP        = 0X1D
    DISCRETE_OUTPUT_GROUP       = 0X1E
    FILE                        = 0X37
    TIME_SYNC                   = 0X43
    ORIGINATOR_CONNECTION_LIST  = 0X45
    TARGET_CONNECTION_LIST      = 0X46
    CIP_SECURITY                = 0X5D
    ETHERNETIP_SECURITY         = 0X5E
    CERTIFICATE_MANAGEMENT      = 0X5F
    AUTHORITY                   = 0X60
    PASSWORD_AUTHENTICATOR      = 0X61
    CERTIFICATE_AUTHENTICATOR   = 0X62
    CONNECTION_CONFIGURATION    = 0XF3


class CIPServiceId(REnum):
    GET_ATTRIBUTES_ALL   = 0X01
    SET_ATTRIBUTES_ALL   = 0X02
    RESET                = 0X05
    START                = 0x06
    STOP                 = 0x07
    CREATE               = 0X08
    DELETE               = 0X09
    GET_ATTRIBUTE_SINGLE = 0X0E
    SET_ATTRIBUTE_SINGLE = 0X10
    NOP                  = 0x17
    GET_MEMBER           = 0x18
    SET_MEMBER           = 0x19
    INSERT_MEMBER        = 0x1A
    REMOVE_MEMBER        = 0x1B
    GET_CONNECTION_POINT_MEMBER_LIST = 0x1D


class CIP_Object_Attribute():
    def __init__(self,
        instance_id=UINT(0),
        attribute_id=UINT(0),
        name='',
        value=None
        ):

        self.instance_id = instance_id
        self.id = attribute_id
        self.value = value
        self.name = name

    def __repr__(self):
        return ('instance_id:  {}\n' .format(self.instace_id) +
                'attribute_id: {}\n'.format(self.id) +
                'value:        {}\n'.self.value(self.value) +
                'name:         {}'.format(self.name)
                )

class CIP_Object_Service():
    def __init__(self, service_id, instance_id, fn, name=''):
        self.instance_id = instance_id
        self.id = service_id
        self.fn = fn
        self.name = name

    def __repr__(self):
        return ('class_id:     {}\n'.format(self.class_id) +
                'service_id:   {}\n' .format(self.id) +
                'attribute_id: {}\n'.format(self.id) +
                'name:         {}'.format(self.name)
                )

class CIP_Object_AttributeList():
    def __init__(self, attributes=[]):
        self.entries = attributes


class CIP_Object_ServiceList():
    def __init__(self, services=[]):
        self.entries = services


class AttributeList(Packet):
    _fields = (
        ('number_of_attributes', UINT(0)),
        ('attributes',  ARRAY(None)),
        )


class ServiceList(Packet):
    _fields = (
        ('number_of_services', UINT(0)),
        ('services',  ARRAY(dtype=UINT)),
        )


class Revision(Packet):
    _fields = (
        ('major', USINT(0)),
        ('minor', USINT(0)),
        )

    def __str__(self):
        return '{}.{}'.format(self.major, self.minor)


CIP_class_attributes = (
    (1, 'revision',                   UINT),
    (2, 'max_instamce',               UINT),
    (3, 'number_of_instances',        UINT),
    (4, 'attribute_list',             AttributeList),
    (5, 'service_list',               ServiceList),
    (6, 'max_class_attribute_id',     UINT),
    (7, 'max_instamce_attribute_id',  UINT),
    )