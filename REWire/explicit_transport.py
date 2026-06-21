import logging
logger = logging.getLogger(__name__)

from .rw_packet import Packet
from .cip_types import *

from .common import (
    CIPGeneralStatus as GSC,
    CIPServiceId,
    CIPObjectId,
    )

from .exceptions import (
    CIPError,
    ExtendedStatus,
    )


class MessageRouterRequest(Packet):
    _fields = (
        ("service",             USINT(0)),
        ("request_path",        PaddedEPATH()),
        ("request_data",        BYTES()),
        )


class MessageRouterResponse(Packet):
    _fields = (
        ("service",         USINT(0)),
        ("padding",         USINT(0)),
        ("general_status",  USINT(0)),
        ("extended_status", ExtendedStatus()),
        ("response_data",   BYTES()),
        )


class ExplicitTransport:

    def cip_service(self, service_id, class_id, instance_id,
                    attribute_id=None, ekey: ELECTRONIC_KEY_SEGMENT=None,
                    data=BYTES(), timeout=5000, rsp_dt=None):

        logger.debug("CIP service:0x{:X}, Class:0x{:X}, Instance:{}{}".format(
            service_id, class_id, instance_id, ", Attribute:{}".format(attribute_id) if attribute_id is not None else ""))

        self.cip_service_send_request(service_id, class_id, instance_id,
                attribute_id, data, ekey=ekey)

        rsp = self.cip_service_rcv_response(service_id, timeout=timeout)

        if rsp_dt is not None:
            return rsp_dt.unpack(rsp)

        return rsp

    def get_attributes_all(self, class_id, instance_id,
            ekey: ELECTRONIC_KEY_SEGMENT=None, rsp_dt=None):

        return self.cip_service(CIPServiceId.GET_ATTRIBUTES_ALL,
                class_id, instance_id, ekey=ekey, rsp_dt=rsp_dt)

    def get_attribute_single(self, class_id, instance_id, attribute_id,
            ekey: ELECTRONIC_KEY_SEGMENT=None, rsp_dt=None):

        return self.cip_service(CIPServiceId.GET_ATTRIBUTE_SINGLE,
                class_id, instance_id, attribute_id, ekey=ekey, rsp_dt=rsp_dt)

    def set_attribute_single(self, class_id, instance_id, attribute_id,
            ekey: ELECTRONIC_KEY_SEGMENT=None, data=BYTES()):
        self.cip_service(CIPServiceId.SET_ATTRIBUTE_SINGLE, class_id,
            instance_id, attribute_id, ekey=ekey, data=data)

    def reset(self, class_id, instance_id, ekey: ELECTRONIC_KEY_SEGMENT=None,
            data=BYTES()):
        return self.cip_service(CIPServiceId.RESET,
                class_id, instance_id, ekey=ekey, data=data)

    @property
    def peer_ip(self):
        raise NotImpementedError()
