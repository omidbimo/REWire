from REWire.rw_packet import Packet
from REWire.cip_types import *
from REWire.cip_object import *
from REWire.common import CIP_class_attributes, Revision, CIP_Services
from REWire.rw_enums import Enum_

class Status(Enum_):
    NOT_VERIFIED = 0
    VERIFIED = 1
    INVALID = 2

class Object0x005F_Services(CIP_Services):
    CREATE_CSR = 0x4B
    VERIFY_CERTIFICATE = 0x4C

class CertificateStatusAndPath(Packet):
    def __init__(self, status=Status.NOT_VERIFIED, path=b''):
        if isinstance(status, int):
            status = USINT(status)
        self.status = status
        if isinstance(path, bytes):
            path = PaddedEPATH(path)
        self.certificate_management_instance = path

    @classmethod
    def dissect(cls, bstream):
        status, bstream = USINT.dissect(bstream)
        path, bstream = PaddedEPATH.dissect(bstream)
        return cls(status, path), bstream

    def __repr__(self):
        return "{}({}, {})".format(self.__class__.__name__,
            Status.name(self.status),
            self.certificate_management_instance)


class CertificateNameAndPath(Packet):
    def __init__(self, name='', path=b''):
        if isinstance(name, str):
            name = SHORT_STRING(name)
        self.certificate_name = name
        if isinstance(path, bytes):
            path = PaddedEPATH(path)
        self.certificate_management_instance = path

    @classmethod
    def dissect(cls, bstream):
        name, bstream = SHORT_STRING.dissect(bstream)
        path, bstream = PaddedEPATH.dissect(bstream)
        return cls(name, path), bstream

    def __str__(self):
        return f"<{self.certificate_name}:[{self.certificate_management_instance}]>"

class CertificateList(ARRAY):
    def __init__(self, certificates=None):
        certificates = certificates or []
        super().__init__(dtype=CertificateNameAndPath, items=certificates)

    def pack(self):
        return USINT.pack(len(self)) + self.pack()

    @classmethod
    def dissect(self, bstream):
        entry_count, bstream = USINT.dissect(bstream)
        return super().dissect(bstream, CertificateNameAndPath, entry_count)

class Object0x005F_Rev3(CIP_ObjectCommon):
    class_id = 0x5F
    class_name = 'Certificate Management Object'
    services = Object0x005F_Services

    _class_attributes = CIP_class_attributes + (
        (8,  'capability_flags', DWORD),
        (9,  'certificate_list', CertificateList),
        (10, 'certificate_encodings_flag', DWORD),
        )

    _instance_attributes = (
        (1, 'name',                 SHORT_STRING),
        (2, 'state',                USINT),
        (3, 'device_certificate',   CertificateStatusAndPath),
        (4, 'ca_certificate',       CertificateStatusAndPath),
        (5, 'certificate_encoding', USINT),
        )

    def get_attributes_all(self, instance_id):
        gaa_attr_list = []
        if instance_id == 0:
            all_gga_attr_list = [1, 2, 6, 7, 8, 9, 10]
        else:
            all_gga_attr_list = [1, 2, 3, 4, 5]

        return super().get_attributes_all(instance_id, all_gga_attr_list)

    def create(self, name):
        return self.client.cip_service(Services.CREATE, class_id=self.class_id,
                instance_id=0, data=SHORT_STRING(name), rsp_dt=UINT)

    def delete(self, instance_id):
        self.client.cip_service(Services.DELETE, class_id=self.class_id,
                instance_id=instance_id)

    def create_csr(self, instance_id, **subject_name):
        """
        param: instace_id: Target instance of Certificate Management Object to create a CSR
        param: subject_name: Optional keyworded arguments as fields of Subject Name:
               SDN (Subject Distinguished Name) arguments:
                    CN (Common Name)
                    O (Organizational name)
                    OU (Organizational Unit)
                    L (Locality or city)
                    ST (State)
                    C (2 letter ISO Country code)
                    emailAddress (Email address of contact)
                    serialNumber (Entity serial number)
               SAN (Subject Alternative Name) arguments:
                    dNSName
                    iPAddress
                    URI
        return PaddedEPATH of created CSR as a File object instance
        """
        valid_SDN = ["CN", "O", "OU", "L", "ST", "C", "emailAddress",
            "serialNumber"]
        valid_SAN = ["dNSName", "iPAddress", "URI"]

        for key, value in subject_name.items():
            if not key in valid_SDN and not key in valid_SAN:
                logger.error("Unknown Subject Name: {}".format(key))

        req_data = b''
        for field in valid_SDN:
            req_data += SHORT_STRING(subject_name.get(field, '')).pack()

        san_str = ''
        for field in valid_SAN:
            san_str += subject_name.get(field, '')
        req_data += SHORT_STRING(san_str).pack()

        san_string = '\n'.join("{}={}".format(key, value) for key, value in subject_name.items() if key in valid_SAN)
        if san_string:
            req_data += SHORT_STRING(san_string).pack()

        return self.client.cip_service(service_id=self.services.CREATE_CSR,
                class_id=self.class_id, instance_id=instance_id, data=req_data,
                rsp_dt=PaddedEPATH)

    def verify_certificate(self, instance_id, cert_id):
        self.client.cip_service(service_id=self.services.VERIFY_CERTIFICATE,
            class_id=self.class_id, instance_id=instance_id, data=UINT(cert_id))
