
from .object0x0001 import *  # Identity object
from .object0x0002 import *  # Message Router object
from .object0x0004 import *  # Assembly object
from .object0x0006 import *  # Connection Manager object
from .object0x0037 import *  # File object
from .object0x005D import *  # CIP Security object
from .object0x005E import *  # EtherNet/IP Security object
from .object0x005F import *  # Certificate Management object
from .object0x0063 import *  # Ingress Egress object

import importlib
import inspect

object_factory_module = importlib.import_module(__name__)

import logging
logging.basicConfig(level=logging.INFO,
    format='%(asctime)s - %(name)s.%(levelname)-8s %(message)s')
logger = logging.getLogger(__name__)

class CIP_ObjectFactory:

    def __new__(cls, client, class_id, revision=None):
        class_name = "Object" + "0x{:04X}".format(class_id)#cls.obj_name_table.get(class_id, None)

        if revision is not None:
            class_name = class_name + "_Rev" + str(revision)
        else:
            # Creating a sorted list of target class in different revisions
            available_revisions = sorted(inspect.getmembers(object_factory_module, lambda member: inspect.isclass(member) and class_name+"_Rev" in member.__name__))
            if not available_revisions:
                raise NotImplementedError("No revisions of {} was found. You are welcomed to implement it.".format(class_name))
            class_name = available_revisions[-1][0]

        logger.debug("Creating an instance of: {}".format(class_name))
        try:
            return getattr(object_factory_module, class_name)(client)
        except Exception as err:
            print(err)
            raise NotImplementedError("No Implementations for {} was found. You are welcomed to implement it.".format(class_name))




