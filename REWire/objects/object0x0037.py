from REWire.rw_packet import Packet
from REWire.cip_types import *
from REWire.cip_object import *
from REWire.common     import *
from REWire.rw_enums import EnumThatWorks

from time import sleep
import logging
logger = logging.getLogger(__name__)


class Object0x0037_Services(CIPServiceId):
    INITIATE_UPLOAD = 0x4B
    INITIATE_DOWNLOAD = 0x4C
    UPLOAD_TRANSFER = 0x4F
    DOWNLOAD_TRANSFER = 0x50
    CLEAR_FILE = 0x51

class State(EnumThatWorks):
    NONEXISTENT = 0
    FILE_EMPTY = 1
    FILE_LOADED = 2
    TRANSFER_UPLOAD_INITIATED = 3
    TRANSFER_DOWNLOAD_INITIATED = 4
    TRANSFER_UPLOAD_IN_PROGRESS = 5
    TRANSFER_DOWNLOAD_IN_PROGRESS = 6
    STORING = 7

class CIP_FileEncodingFormat(EnumThatWorks):
    BINARY = 0
    COMPRESSED = 1
    PEM_ENCODEDCERTIFICATE  = 2
    PKCS7_ENCODEDCERTIFICATE= 3
    PEM_ENCODEDCRL = 4
    PKCS7_ENCODEDCRL = 5
    TEXT = 11
    WORD = 12
    EXCEL = 13
    PDF = 14

class CIP_FileInvocationMethod(EnumThatWorks):
    NOACTIONREQUIRED = 0
    RESETTOIDENTITYOBJECT = 1
    POWERCYCLEONDEVICE = 2
    STARTSERVICEREQUEST = 3
    APPLICATIONOBJECTINTERNALREQUEST = 4
    NOTAPPLICABLE = 255

class CIP_FilePacketType(EnumThatWorks):
    FIRST_PACKET = 0
    MIDDLE_PACKET = 1
    LAST_PACKET = 2
    ABORT_PACKET = 3
    FIRST_AND_LAST_PACKET = 4

class CIP_FILE_SAVE_PARAMETER(EnumThatWorks):
    AUTOSAVE = 0
    SAVESERVICE = 1
    VOLATILE = 2
    CUSTOM = 3
    CUSTOMANDSAVESERVICE = 4

class CIP_FILE_ACCESS_RULE(EnumThatWorks):
    READWRITE = 0
    READONLY  = 1

class InitiateUploadRequest(Packet):
    _fields = (
        ("maximum_transfer_size", USINT()),
        )

    def __init__(self, max_transfer_size=0xFF):
        self.maximum_transfer_size = USINT(max_transfer_size)


class InitiateUploadResponse(Packet):
    _fields = (
        ("file_size", UDINT()),
        ("transfer_size", USINT()),
        )


class InitiateDownloadRequest(Packet):
    _fields = (
        ("file_size", UDINT()),
        ("file_format_version", UINT()),
        ("file_revision", UINT()),
        ("file_name", STRINGI()),
        )


class InitiateDownloadResponse(Packet):
    _fields = (
        ("incremental_burn", UDINT()),
        ("incremental_burn_time", UINT()),
        ("transfer_size", USINT()),
        )


class UploadTransferRequest(Packet):
    _fields = (
        ("transfer_number", USINT()),
        )

    def __init__(self, transfer_number):
        self.transfer_number = USINT(transfer_number)


class UploadTransferResponse(Packet):
    _fields = (
        ("transfer_number", USINT()),
        ("transfer_packet_type", USINT()),
        ("file_data", BYTES()),
        )


class DownloadTransferRequest(Packet):
    _fields = (
        ("transfer_number", USINT()),
        ("transfer_packet_type", USINT()),
        ("file_data", BYTES()),
        #("transfer_checksum", UINT()),
        )

    def __init__(self, transfer_number, transfer_packet_type, file_data):
        self.transfer_number = USINT(transfer_number)
        self.transfer_packet_type = USINT(transfer_packet_type)
        self.file_data = file_data


class DownloadTransferResponse(Packet):
    _fields = (
        ("transfer_number", USINT()),
        )


class CreateRequest(Packet):
    _fields = (
        ("instance_name", STRINGI()),
        ("encoding", USINT()),
        )

    def __init__(self, instance_name, encoding):
        self.instance_name = STRINGI(instance_name)
        self.encoding = USINT(encoding)


class CreateResponse(Packet):
    _fields = (
        ("instance_number", UINT()),
        ("invocation_method", USINT()),
        )


class FileDirectoryItem(Packet):
    _fields = (
        ("instance_id",     UINT()),
        ("instance_name",   STRINGI()),
        ("file_name",       STRINGI()),
        )


class FileDirectory(ARRAY):
    def __init__(self, entries=None):
        entries = entries or []
        super(FileDirectory, self).__init__(dtype=FileDirectoryItem, items=entries)

    def __str__(self):
        return "\n".join(("Instance Id.: {}\n".format(entry.instance_id) +
                          "    Instance name: \"{}\"\n".format(entry.instance_name) +
                          "    File name: \"{}\"".format(entry.file_name))
                          for entry in self)

    @classmethod
    def dissect(cls, bstream):
        return super().dissect(bstream, dtype=FileDirectoryItem)

class FileTransferContext():
    def __init__(self):
        self.service_id                 = 0
        self.instance_id                = 0
        self.file_name                  = 0
        self.file_size                  = 0
        self.file_format_version        = 0
        self.file_revision              = 0
        self.file_data                  = BYTES()
        self.transfer_number            = 0
        self.response_transfer_number   = 0
        self.transfer_size              = 0
        self.packet_type                = 0
        self.checksum                   = UINT(0)
        self.fragment_data              = ""
        self.burn_buffer_size           = 0
        self.burn_time                  = 0

    def __str__(self):
        return ( "Service_id:      {}\n".format(self.service_id)
               + "Instance_id:     {}\n".format(self.instance_id)
               + "TransferNumber: {}\n".format(self.transfer_number)
               + "transfer_size:   {}\n".format(self.transfer_size)
               + "PacketType:     {}\n".format(self.packet_type)
               + "FileName:       {}\n".format(self.file_name)
               + "file_size:       {}\n".format(self.file_size)
               + "Checksum:       {}\n".format(self.checksum)
               + "FragmentData:   {}\n".format("...")
               + "BurnBufferSize: {}\n".format(self.burn_buffer_size)
               + "BurnTime:       {}\n".format(self.burn_time)
               )


class Object0x0037_Rev3(CIP_ObjectCommon):
    class_id = 0x37
    class_name = "File Object"
    services = Object0x0037_Services

    _class_attributes = CIP_class_attributes + (
        (32, "directory", FileDirectory),
        )

    _instance_attributes = (
        (1,  "state",                       USINT),
        (2,  "instance_name",               STRINGI),
        (3,  "file_format_version",         UINT),
        (4,  "file_name",                   STRINGI),
        (5,  "file_revision",               UINT),
        (6,  "file_size",                   UDINT),
        (7,  "file_checksum",               UINT),
        (8,  "invocation_method",           USINT),
        (9,  "file_save_parameters",        BYTE),
        (10, "file_access_rule",            USINT),
        (11, "file_encoding_format",        USINT),
        (12, "transfer_session_timeout",    USINT),
        )

    def file_checksum(self, file_data):
        chk = 0
        for i in range(len(file_data)):
            byte, file_data = USINT.dissect(file_data)
            chk += int(byte) # Convert to int to avoid UISNT overflow
        chk = (0x10000 - (chk & 0x0000FFFF)) & 0xFFFF
        return chk

    def incremental_file_checksum(self, fragment_data, rolled_checksum, last_fragment=False):
        """
        Incrementally calculates the chacksum of multiple data chunks
        Each call requires the checksum from the previous call.

        """
        rolled_checksum += sum((octet for octet in fragment_data))
        if last_fragment:
            rolled_checksum = (0x10000 - (rolled_checksum & 0x0000FFFF)) & 0xFFFF
        return rolled_checksum

    def transfer_step(self, transfer_session):
        if transfer_session.service_id == self.services.INITIATE_UPLOAD:
            service_data = self.client.cip_service(transfer_session.service_id,
                self.class_id, transfer_session.instance_id,
                data=InitiateUploadRequest(transfer_session.transfer_size).pack()
                )

            rsp = InitiateUploadResponse().unpack(service_data)
            transfer_session.file_size = rsp.file_size
            transfer_session.transfer_size = rsp.transfer_size

        elif transfer_session.service_id == self.services.UPLOAD_TRANSFER:
            req_data = UploadTransferRequest(transfer_session.transfer_number).pack()
            service_data = self.client.cip_service(transfer_session.service_id,
                self.class_id, transfer_session.instance_id,
                data=UploadTransferRequest(transfer_session.transfer_number).pack()
                )
            rsp = UploadTransferResponse().unpack(service_data)
            transfer_session.response_transfer_number = rsp.transfer_number
            transfer_session.packet_type = rsp.transfer_packet_type
            transfer_session.fragment_data = rsp.file_data

        elif transfer_session.service_id == self.services.INITIATE_DOWNLOAD:
            req_data = InitiateDownloadRequest(transfer_session.file_size,
                            transfer_session.file_format_version,
                            transfer_session.file_revision,
                            transfer_session.file_name).pack()
            service_data = self.client.cip_service(transfer_session.service_id,
                    self.class_id, transfer_session.instance_id, data=req_data)
            rsp = InitiateDownloadResponse().unpack(service_data)
            transfer_session.burn_buffer_size = rsp.incremental_burn
            transfer_session.burn_time = rsp.incremental_burn_time
            transfer_session.transfer_size = rsp.transfer_size

        elif transfer_session.service_id == self.services.DOWNLOAD_TRANSFER:
            req_data = DownloadTransferRequest(transfer_session.transfer_number,
                            transfer_session.packet_type,
                            transfer_session.fragment_data).pack()
            service_data = self.client.cip_service(transfer_session.service_id,
                    self.class_id, transfer_session.instance_id, data=req_data)
            rsp = DownloadTransferResponse().unpack(service_data)
            transfer_session.response_transfer_number = rsp.transfer_number

    def upload(self, instance_id, max_transfer_size = 0xFF):
        transfer_session = FileTransferContext()

        transfer_session.service_id = self.services.INITIATE_UPLOAD
        transfer_session.instance_id = instance_id
        transfer_session.transfer_size = max_transfer_size
        self.transfer_step(transfer_session)

        transfer_session.transfer_number = 0
        transfer_session.file_content = ""
        transfer_session.service_id = self.services.UPLOAD_TRANSFER

        while (transfer_session.packet_type != CIP_FilePacketType.LAST_PACKET and
               transfer_session.packet_type != CIP_FilePacketType.FIRST_AND_LAST_PACKET):
            self.transfer_step(transfer_session)
            transfer_session.file_data += transfer_session.fragment_data
            transfer_session.transfer_number = (transfer_session.transfer_number + 1) & 0xFF

        transfer_session.checksum.unpack(transfer_session.fragment_data[-2:])
        transfer_session.file_data = transfer_session.file_data[:-2]

        if self.file_checksum(transfer_session.file_data) != transfer_session.checksum:
            raise Exception("Unexpected Checksum! Expected:{}, got:{} ".format(
                    self.file_checksum(transfer_session.file_data), transfer_session.checksum))

        if len(transfer_session.file_data) != transfer_session.file_size:
            raise Exception("Unexpected file size! Expected:{} bytes, got:{} bytes ".format(
                transfer_session.file_size, len(transfer_session.file_data)))

        return transfer_session.file_data.decode("utf-8")

    def download(self, instance_id, file_name, file_data, file_format_version=1, file_revision=0x11):
        transfer_session = FileTransferContext()
        transfer_session.service_id          = self.services.INITIATE_DOWNLOAD
        transfer_session.instance_id         = instance_id
        transfer_session.file_name           = file_name
        transfer_session.file_size           = len(file_data)
        transfer_session.file_data           = bytes(file_data, "utf-8")
        transfer_session.file_format_version = file_format_version
        transfer_session.file_revision       = file_revision
        transfer_session.checksum            = None
        self.transfer_step(transfer_session)
        # Make sure at least one fragent will be transferred.(special case is when the file size is zero)
        fragment_count = max(((transfer_session.file_size + transfer_session.transfer_size - 1) // transfer_session.transfer_size), 1)
        file_offset = 0
        rolled_checksum = 0
        transfer_session.service_id = self.services.DOWNLOAD_TRANSFER

        for transfer_id in range(fragment_count):

            transfer_session.transfer_number = transfer_id & 0xFF

            if (transfer_id == 0) and (transfer_session.file_size > transfer_session.transfer_size):
                transfer_session.packet_type = CIP_FilePacketType.FIRST_PACKET
            elif (transfer_id == 0) and (transfer_session.file_size <= transfer_session.transfer_size):
                transfer_session.packet_type = CIP_FilePacketType.FIRST_AND_LAST_PACKET
                transfer_session.transfer_size = transfer_session.file_size
            elif transfer_id == (fragment_count - 1):
                transfer_session.packet_type = CIP_FilePacketType.LAST_PACKET
                transfer_session.transfer_size = transfer_session.file_size - file_offset
            else:
                transfer_session.packet_type = CIP_FilePacketType.MIDDLE_PACKET

            transfer_session.fragment_data = transfer_session.file_data[file_offset:(file_offset + transfer_session.transfer_size)]
            file_offset += transfer_session.transfer_size

            rolled_checksum = self.incremental_file_checksum(transfer_session.fragment_data,
                rolled_checksum,
                (transfer_session.packet_type == CIP_FilePacketType.LAST_PACKET) or
                (transfer_session.packet_type == CIP_FilePacketType.FIRST_AND_LAST_PACKET))

            if (transfer_session.packet_type == CIP_FilePacketType.LAST_PACKET or
                transfer_session.packet_type == CIP_FilePacketType.FIRST_AND_LAST_PACKET):
                transfer_session.fragment_data += UINT(rolled_checksum).pack()

            self.transfer_step(transfer_session)
            #TODO improve the out of sequence transfer
            assert(transfer_session.response_transfer_number == transfer_session.transfer_number)

    def create(self, instance_name, encoding=0):
        service_data = self.client.cip_service(self.services.CREATE,
            self.class_id, 0, data=CreateRequest(instance_name, encoding).pack()
            )
        rsp = CreateResponse().unpack(service_data)
        return rsp.instance_number, rsp.invocation_method

    def clear_file(self, instance_id):
        #TODO
        pass

    def delete(self, instance_id):
        service_data = self.client.cip_service(self.services.DELETE, self.class_id,
                instance_id)
