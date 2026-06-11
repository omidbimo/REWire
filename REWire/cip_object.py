from REWire.common import *

import logging
logging.basicConfig(level=logging.INFO,
    format='%(asctime)s - %(name)s.%(levelname)-8s %(message)s')
logger = logging.getLogger(__name__)

from collections import namedtuple
ATTR_DESC_ITEM = namedtuple('ATTR_DESC_ITEM', 'id name type')

__all__ = [
    'CIP_ObjectCommon',
    'ATTR_DESC_ITEM',
    ]

class Attributes():
    pass

class CIP_ObjectMeta(type):

    def __new__(cls, name, bases, dict):

        new_ = super(CIP_ObjectMeta, cls).__new__(cls, name, bases, dict)

        attr_info = {}
        slots = []
        cls_attributes = getattr(new_, '_class_attributes', None)

        slots.append('class_attr')
        slots.append('instance_attr')

        slots.append('client')

        dict['__slots__'] = slots

        new_ = super(CIP_ObjectMeta, cls).__new__(cls, name, bases, dict)

        return new_

class CIP_ObjectCommon(metaclass = CIP_ObjectMeta):
    __slots__ = ()
    def __init__(self, client):
        self.client = client
        self.class_attr = Attributes()
        self.instance_attr = Attributes()

        desc = getattr(self, '_class_attributes', None)
        if desc is not None:
            for item in desc:
                setattr(self.class_attr, str(item[1]), item[2]())

        desc = getattr(self, '_instance_attributes', None)
        if desc is not None:
            for item in desc:
                setattr(self.instance_attr, str(item[1]), item[2]())

    def get_attr_type(self, instance_id, attribute_id):
        attr_type = None
        if instance_id == 0:
            desc = getattr(self, '_class_attributes', None)
        else:
            desc = getattr(self, '_instance_attributes', None)
        if desc is not None:
            attr_type = next((attr[2] for attr in desc if attr[0] == attribute_id), None)

        return attr_type

    def get_attribute_single(self, instance_id, attribute_id):
        # Retrieving attribute's data type from type dictionary
        rsp_dt = self.get_attr_type(instance_id, attribute_id)

        if rsp_dt is None:
            logger.warning('Unable to find the data type of class:0x{:X}, instance:{}, attribute:{}'.format(
                self.class_id, instance_id, attribute_id))

        rsp = self.client.cip_service(CIP_Services.GET_ATTRIBUTE_SINGLE,
                self.class_id, instance_id, attribute_id, rsp_dt=rsp_dt)

        return rsp

    def set_attribute_single(self, instance_id, attribute_id, data):
        rsp = self.client.cip_service(CIP_Services.SET_ATTRIBUTE_SINGLE,
                self.class_id, instance_id, attribute_id, data=data)


    def get_attributes_all(self, instance_id, gaa_attr_id_list: list):
        gaa_dict = {}
        gaa = self.client.get_attributes_all(class_id=self.class_id, instance_id=instance_id)

        for attribute_id in gaa_attr_id_list:
            if len(gaa) == 0:
                break
            attr = self.get_attr_type(instance_id, attribute_id)()
            gaa = attr.dissect(gaa)
            gaa_dict.update({attribute_id: attr})

        if len(gaa) != 0:
            raise Exception("Unexpected {} bytes excess data in the get_attributes_all response.".format(len(gaa)))
        return gaa_dict