from REWire.rw_packet import Packet
from REWire.cip_types import *
from REWire.cip_object import *
from REWire.common import CIP_class_attributes, Revision, CIPServiceId

class Object0x0001_Services(CIPServiceId):
    FLASH_LEDS = 0x4B
    CERTIFICATE_CHALLENGE = 0x4C


class Semaphore(Packet):
    _fields = (
        ("vendor_number", UINT(0)),
        ("client_serial_number", UDINT(0)),
        ("millisecond_timer", ITIME(0)),
        )


class ISO_639_2_lang(BYTES):
    def __new__(cls, value=b"eng"):
        if len(value) != 3:
            raise Exception(f"Invalid ISO 639-2/T language: {value}")
        return super().__new__(cls, value)


class Object0x0001_Rev2(CIP_ObjectCommon):
    class_id = 0x01
    class_name = "Identity Object"
    services = Object0x0001_Services
    _class_attributes = CIP_class_attributes

    _instance_attributes = (
        (1,  "vendor_id",                         UINT),
        (2,  "device_type",                       UINT),
        (3,  "product_code",                      UINT),
        (4,  "revision",                          Revision),
        (5,  "status",                            WORD),
        (6,  "serial_number",                     UDINT),
        (7,  "product_name",                      SHORT_STRING),
        (8,  "state",                             USINT),
        (9,  "configuration_consistency_value",   UINT),
        (10, "heartbeat_interval",                USINT),
        (11, "active_language",                   ISO_639_2_lang),
        (12, "supported_language_list",           ISO_639_2_lang),
        (13, "international_product_name",        STRINGI),
        (14, "semaphore",                         Semaphore),
        (15, "assigned_nname",                    STRINGI),
        (16, "assigned_description",              STRINGI),
        (17, "geographic_location",               STRINGI),
        (18, "modbus_identity_info",              BYTES),
        (19, "protection_mode",                   WORD),
        (20, "uptime",                            UDINT),
        (21, "catalog_number",                    SHORT_STRING),
        (22, "manufacture_date",                  DATE),
        (23, "hart_extended_identity_info",       BYTES),
        (24, "hart_status",                       BYTES),
        (25, "application_profiles",              BYTES),
        (26, "io-link_protocol_revision_id",      BYTES),
        (27, "io-link_functionid",                BYTES),
        (28, "io-link_serial_number",             BYTES),
        (29, "extended_io-link_identity_info",    BYTES),
        (30, "supported_language_list2",          BYTES),
        (31, "vendor_name",                       STRING),
        (32, "vendor_uri",                        STRING),
        (33, "configuration_counter",             DINT),
        (34, "configuration_date",                STIME),
        (35, "manufacture_serial_number",         SHORT_STRING),
        (36, "device_manual",                     BYTES),
        (37, "hardware_revision",                 UINT),
        (38, "supported_device_type_revisions",   BYTES),
        (39, "product_identity_certificate",      BYTES),
        (40, "io_link_hw_id_key",                 BYTES),
        )

    def get_attributes_all(self, instance_id):
        gaa_attr_list = []
        if instance_id == 0:
            all_gga_attr_list = [1, 2, 6, 7]
        else:
            object_revision = self.client.get_attribute_single(
                class_id=self.class_id, instance_id=0, attribute_id=1, rsp_dt=UINT)

            if object_revision == 1:
               all_gga_attr_list = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 14, 19, 20, 21, 22, 33, 34, 37, 38]
            elif object_revision == 2:
               all_gga_attr_list = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 14, 19, 20, 21, 22, 33, 34, 37, 38]
            else:
                raise NotImplementedError

        return super(Object0x0001_Rev2, self).get_attributes_all(instance_id, all_gga_attr_list)


    def reset(self, instance_id=0, type=0):
        self.client.cip_service(self.services.RESET, self.class_id,
                instance_id=instance_id, data=USINT(type))

    def flash_leds(self, time):
        self.client.cip_service(self.services.FLASH_LEDS, self.class_id,
                instance_id=1, data=USINT(time))

