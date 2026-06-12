from REWire.rw_packet import Packet
from REWire.rw_enum import EnumThatWorks
from REWire.cip_types import *
from REWire.cip_object import *
from REWire.common import *

class Object0x0005_Services(CIPServiceId):
    pass

class State(EnumThatWorks):
    NONEXISTENT = 0
    CONFIGURING = 1
    WAITING_FOR_CONNECTION_ID = 2
    ESTABLISHED = 3
    TIMED_OUT = 4
    DEFERRED_DELETE = 5
    CLOSING = 6

class ConnectionInstanceType(EnumThatWorks):
    EXPLICIT_MESSAGING = 0
    IO_MESSAGING = 1
    CIP_BRIGED = 2

class TransportClass(EnumThatWorks):
    CLASS0 = 0
    CLASS1 = 1
    CLASS2 = 2
    CLASS3 = 3

class ProductionTrigger(EnumThatWorks):
    CYCLIC = 0
    CHANGE_OF_STATE = 1
    APPLICATION_OBJECT = 2

class TransportDirection(EnumThatWorks):
    CLIENT = 0
    SERVER = 1

class TransportClassTrigger():
    def __init__(self, transport_class, trigger, direction):
        self.transport_class = transport_class
        self.production_trigger = trigger
        self.direction = direction

    def pack(self):
        return USINT(
                (self.transport_class & 0x0F) |
                ((self.production_trigger & 0x07) << 4) |
                ((self.direction & 0x01) << 7)
                ).pack()

class Class3PDU(Packet):
    _fields = (
        ('sequence_count', UINT(0)),
        ('payload', BYTES()),
        )

    def __init__(self, payload):
        super(Class3PDU, self).__init__()
        self.payload = BYTES(payload)

class Object0x0005_Rev2(CIP_ObjectCommon):
    class_id = 0x05
    class_name = "Connection Object"
    services = Object0x0005_Services
    _class_attributes = CIP_class_attributes
    connection_request_error_count = 0
    safety_connection_counters = 0

    _instance_attributes = (

        )

