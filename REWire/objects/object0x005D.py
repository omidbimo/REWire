from REWire.rw_packet import Packet
from REWire.cip_types import *
from REWire.cip_object import *
from REWire.common     import CIP_class_attributes, Revision, CIPServiceId
from REWire.rw_enum import REnum

class State(REnum):
    FACTORY_DEFAULT_CONFIGURATION = 0
    CONFIGURATION_IN_PROGRESS = 1
    CONFIGURED = 2
    INCOMPLETE_CONFIGURATION = 3


class Object0x005D_Services(CIPServiceId):
    BEGIN_CONFIG = 0x4B
    KICK_TIMER = 0x4C
    END_CONFIG = 0x4D
    OBJECT_CLEANUP = 0x4E


class ObjectAuthorization(Packet):
    _fields = (
        ('number_of_entries',   UINT(0)),
        ('object_code',         UDINT(0)),
        ('service_code',        USINT(0)),
        ('reserved',            BYTE(0)),
        ('roles_required',      DWORD(0)),
        )


class Object0x005D_Rev4(CIPObjectCommon):
    class_id = 0x5D
    class_name = 'CIP Security Object'
    services = Object0x005D_Services

    _class_attributes = CIP_class_attributes

    _instance_attributes = (
        (1, 'state',                          USINT),
        (2, 'security_profiles',              WORD),
        (3, 'security_profiles_configured',   WORD),
        (4, 'object_authorization',           ObjectAuthorization)
        )

    def get_attributes_all(self, instance_id):
        gaa_attr_list = []
        if instance_id == 0:
            all_gga_attr_list = [1, 2, 6, 7]
        else:
            all_gga_attr_list = [1, 2]

        return super(Object0x005D, self).get_attributes_all(instance_id, all_gga_attr_list)

    def begin_config(self):
        self.client.cip_service(self.services.BEGIN_CONFIG, self.class_id, 1)

    def kick_timer(self):
        self.client.cip_service(self.services.KICK_TIMER, self.class_id, 1)

    def end_config(self):
        self.client.cip_service(self.services.END_CONFIG, self.class_id, 1)

    def object_cleanup(self):
        self.client.cip_service(self.services.OBJECT_CLEANUP, self.class_id, 1)
