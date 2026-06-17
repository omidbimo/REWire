from REWire.cip_types import Packet
from REWire.cip_types import *
from REWire.cip_object import *
from REWire.common import CIP_class_attributes, Revision, CIPServiceId
from REWire.rw_enum import REnum
from REWire.tls_cipher_suites import *

import string
import random
from os import urandom

class State(REnum):
    FACTORY_DEFAULT_CONFIGURATION = 0
    CONFIGURATION_IN_PROGRESS = 1
    CONFIGURED = 2
    PULL_MODEL_IN_PROGRESS = 3
    PULL_MODEL_COMPLETED = 4
    PULL_MODEL_DISABLED = 5

class Object0x005E_Services(CIPServiceId):
    BEGIN_CONFIG = 0x4B
    KICK_TIMER = 0x4C
    APPLY_CONFIG = 0x4D
    ABORT_CONFIG = 0x4E

class PSK_Usage(REnum):
    SERVER = 0
    CLIENT = 1
    ANY_USAGE = 2


class CipherSuite(UINT):

    def __new__(cls, value: int=0):
        return super().__new__(cls, value)

    def __str__(self):
        high_low_bytes = self.to_bytes(2, byteorder='little')
        cipher_id = f"0x{high_low_bytes[0]:02X}{high_low_bytes[1]:02X}"
        return f"<{cipher_id}: {TLSCipherSuite(int(cipher_id, 16)).name}>"

class CipherSuites(ARRAY):
    def __init__(self, ciphers=[]):
        super().__init__(CipherSuite, ciphers)

    def pack(self):
        return USINT(len(self)).pack() + self.pck()

    @classmethod
    def dissect(cls, bstream):
        count, bstream = USINT.dissect(bstream)
        return super().dissect(bstream, CipherSuite, count)
    """
    def __iadd__(self, other):
        if isinstance(other, CipherSuite):
            if other not in self.cipher_suites:
                self.cipher_suites += other

        elif isinstance(other, CipherSuites):
            for ciper_suite in other:
                self.cipher_suites += ciper_suite
        elif isinstance(other, BYTES) and len(other) == 2:
            if other not in self.cipher_suites:
                self.cipher_suites += other
        elif isinstance(other, bytes) and len(other) == 2:
            if CipherSuite(other) not in self.cipher_suites:
                self.cipher_suites += CipherSuite(other)
        elif isinstance(other, int) and other < 0xFFFF:
            if CipherSuite(other) not in self.cipher_suites:
                self.cipher_suites += CipherSuite(other)
        else:
            raise TypeError(type(other), len(other))
        self.number_of_cipher_suites = USINT(len(self.cipher_suites))
        return self

    def __isub__(self, other):
        if isinstance(other, CipherSuites):
            for cipher_suite in other.cipher_suites:
                if cipher_suite in self.cipher_suites:
                    self.cipher_suites.remove(cipher_suite)
        elif isinstance(other, CipherSuite):
            for cipher_suite in self.cipher_suites:
                if cipher_suite == other:
                    self.cipher_suites.remove(cipher_suite)
        elif isinstance(other, int) and other < 0xFFFF:
            for cipher_suite in self.cipher_suites:
                if cipher_suite == CipherSuite(other):
                    self.cipher_suites.remove(cipher_suite)
        elif isinstance(other, bytes) and len(other) == 2:
            for cipher_suite in self.cipher_suites:
                if cipher_suite == CipherSuite(other):
                    self.cipher_suites.remove(cipher_suite)
        else:
            raise TypeError(type(other))
        self.number_of_cipher_suites = USINT(len(self.cipher_suites))
        return self

    def __iter__(self):
        for item in self.cipher_suites:
            yield item

    def __len__(self):
        return len(self.cipher_suites)

    def __str__(self):
        return ('<{} cipher suites: '.format(len(self.cipher_suites)) +
            '['+ ', '.join('{}'.format(cs) for cs in self.cipher_suites) + ']>')
    """
class PSK(Packet):

    def __init__(self, id=b'', secret=b'', usage=PSK_Usage.SERVER):
        super().__init__()

        if isinstance(id, str):
            id = id.to_bytes()
        if isinstance(id, str):
            secret = secret.to_bytes()

        self.size_of_psk_identity = USINT(len(id))
        self.psk_identity = BYTES(id)
        self.size_of_psk = USINT(len(secret))
        self.psk = BYTES(secret)
        self.psk_usage = USINT(usage)

    @classmethod
    def generate(cls, id='', secret=b'', usage=0):
        if not id:
            id = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase + string.digits) for _ in range(128))

        if not secret:
            secret=urandom(64)
        return PSK(id=id, secret=secret, usage=usage)

    def pack(self):
        return  self.size_of_psk_identity.pack() + \
                self.psk_identity.pack() + \
                self.size_of_psk.pack() + \
                self.psk.pack() + \
                self.psk_usage.pack()

    @classmethod
    def dissect(cls, bstream):
        psk_id, bstream = SHORT_STRING.dissect(bstream)
        secret, bstream = SHORT_STRING.dissect(bstream)
        usage, bstream = USINT.dissect(bstream)
        instance = cls()
        return instance, bstream

    def __eq__(self , other):
        return (self.size_of_psk_identity == other.size_of_psk_identity and
                self.psk_identity == other.psk_identity and
                self.size_of_psk == other.size_of_psk and
                self.psk == other.psk and
                self.psk_usage == other.psk_usage)

    def __repr__(self):
        return "PSK(id:\"{}\", secret:\"{}\", usage: \"{}\"({}))".format(self.psk_identity,
            self.psk, self.psk_usage, PSK_Usage.name(self.psk_usage))


class PreSharedKeys(ARRAY):

    def pack(self):
        return USINT(len(self)).pack() + self.pack()

    @classmethod
    def dissect(cls, bstream):
        entry_count, bstream = USINT.unpack(bstream)
        return super().dissect(bstream, PSK, entry_count)


class CertificatesPath(ARRAY):
    def pack(self):
        return USINT(len(self)) + self.pack()

    @classmethod
    def dissect(cls, bstream):
        entry_count, bstream = USINT.dissect(bstream)
        return super().dissect(bstream, PaddedEPATH, entry_count)


class Object0x005E_Rev9(CIP_ObjectCommon):
    class_id = 0x5E
    class_name = 'EtherNetIP Security Object'
    services = Object0x005E_Services

    _class_attributes = CIP_class_attributes + (
        (8, 'number_of_psks_supported', UINT),
        (9, 'psk_usages_supported', BYTE),
        )

    _instance_attributes = (
        (1,  'state',                                 USINT),
        (2,  'capability_flags',                      DWORD),
        (3,  'available_cipher_suites',               CipherSuites),
        (4,  'allowed_cipher_suites',                 CipherSuites),
        (5,  'preshared_keys',                        PreSharedKeys),
        (6,  'active_device_certificates',            CertificatesPath),
        (7,  'trusted_authorities',                   CertificatesPath),
        (8,  'certificate_revocation_list',           CertificatesPath),
        (9,  'verify_client_certificate',             BOOL),
        (10, 'send_certificate_chain',                BOOL),
        (11, 'check_expiration',                      BOOL),
        (12, 'trusted_identities',                    CertificatesPath),
        (13, 'pull_model_enable',                     BOOL),
        (14, 'pull_model_status',                     UINT),
        (15, 'dtls_timeout',                          UINT),
        (16, 'udp_only_poicy',                        USINT),
        (17, 'check_subject_alternative_name',        BOOL),
        (18, 'available_originator_cipher_suites',    CipherSuites),
        (19, 'allowed_originator_cipher_suites',      CipherSuites),
        )

    def get_attributes_all(self, instance_id):
        gaa_attr_list = []
        if instance_id == 0:
            all_gga_attr_list = [1, 2, 6, 7]
        else:
            all_gga_attr_list = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17]

        return super(Object0x005E, self).get_attributes_all(instance_id, all_gga_attr_list)

    def begin_config(self):
        self.client.cip_service(self.services.BEGIN_CONFIG, self.class_id, 1)

    def kick_timer(self):
        self.client.cip_service(self.services.KICK_TIMER, self.class_id, 1)

    def apply_config(self, cleanup_objects=True, drop_connections=False, close_delay=3000):
        """"
        param: cleanup_objects: If True, the target must clean up the unused security related instances.
        param: drop_connections: If True, the server must terminate all ongoing
               connections.
        param: close_delay: Determines the time the server shall delay to drop the connections.
        return: -
        """
        apply_behavior = (1 << 0) if drop_connections else 0
        apply_behavior |= (1 << 1) if cleanup_objects else 0

        self.client.cip_service(self.services.APPLY_CONFIG, self.class_id, 1,
            data=WORD(apply_behavior).pack() + UINT(close_delay).pack())

    def abort_config(self):
        self.client.cip_service(self.services.ABORT_CONFIG, self.class_id, 1)

