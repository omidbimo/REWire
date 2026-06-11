from enum import IntEnum
from REWire.rw_packet import Packet
from REWire.cip_types import *
from REWire.rw_enums import Enum_

class CIPObjectId(IntEnum):
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

class CIP_Services(Enum_):
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

class CIP_Object_ClassAttributes():
    def __init__(self,
        revision,
        max_instamce,
        number_of_instances,
        attribute_list,
        service_list,
        max_class_attribute_id,
        max_instamce_attribute_id
        ):

        self.revision = revision
        self.max_instamce = max_instamce
        self.number_of_instances = number_of_instances
        self.attribute_list = attribute_list
        self.service_list = service_list
        self.max_class_attribute_id = max_class_attribute_id
        self.max_instamce_attribute_id = max_instamce_attribute_id

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