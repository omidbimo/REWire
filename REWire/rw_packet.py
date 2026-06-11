"""
  Copyright (c) 2004 Dug Song <dugsong@monkey.org>
  Copyright (c) 2026 Omid Kompani

  All rights reserved, all wrongs reversed.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:

  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in the
     documentation and/or other materials provided with the distribution.
  3. The names of the authors and copyright holders may not be used to
     endorse or promote products derived from this software without
     specific prior written permission.

  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
  AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
  THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
  OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
  ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

import copy
import logging
logger = logging.getLogger(__name__)

__all__ = [ "Packet" ]

class MetaPacket(type):
    def __new__(cls, name, bases, dict):
        new_ = super().__new__(cls, name, bases, dict)
        fields_ = getattr(new_, "_fields", None)

        if fields_ is not None:
            dict["__slots__"] = [attr_name for attr_name, default in fields_]
            new_ = super().__new__(cls, name, bases, dict)

        return new_

class Packet(metaclass=MetaPacket):
    __slots__ = ()

    def __init__(self, *args, **kwargs):
        fields_ = getattr(self, "_fields", None)

        # setting the default values
        for attr_name, default in fields_:
            setattr(self, attr_name, copy.deepcopy(default))

        for index, arg in enumerate(args):
            attr_name = fields_[index][0]
            attr_type = type(fields_[index][1])
            if isinstance(arg, attr_type):
                setattr(self, attr_name, arg)
            else:
                setattr(self, attr_name, attr_type(arg))

        for attr_name, attr_value in kwargs.items():
            default = next((default for name, default in fields_ if name == attr_name), None)
            attr_type = type(default)
            if isinstance(attr_value, attr_type):
                setattr(self, attr_name, attr_value)
            else:
                setattr(self, attr_name, attr_type(attr_value))

    def pack(self):
        packed = bytes()
        for attr_name in self.__slots__:
            attr = getattr(self, attr_name)
            #logger.debug("Packing {}.{} {}({})".format(self.__class__.__name__, attr_name, type(attr), attr))

            if isinstance(attr, bytearray) or isinstance(attr, bytes):
                packed += attr
                continue
            packed += attr.pack()
        return packed

    @classmethod
    def dissect(cls, bstream):
        new_instance = cls()

        for attr_name in cls.__slots__:
            attr = getattr(new_instance, attr_name)
            logger.debug(f"Unpack {type(attr)} '{attr_name}'")

            attr, bstream = attr.dissect(bstream)
            setattr(new_instance, attr_name, attr)

        return new_instance, bstream

    @classmethod
    def unpack(cls, bstream, error_on_excess=True):
        logger.debug(f"Unpack {cls}")
        instance, bstream = cls.dissect(bstream)

        if error_on_excess is True and len(bstream) > 0:
            raise Exception(f"{len(bstream)} bytes Excess data in bstream! {cls.__class__.__name__}")
        return instance

    def __len__(self):
        return sum(len(getattr(self, attr_name)) for attr_name in self.__slots__)

    def __repr__(self):
        return "{}({})".format(self.__class__.__name__,
            ", ".join(str(getattr(self, attr_name, None))
            for attr_name in self.__slots__)
            )

    def __str__(self):
        return "{}(\n    {})".format(self.__class__.__name__,
            "\n    ".join(attr_name + "=" + str(getattr(self, attr_name, None))
            for attr_name in self.__slots__)
            )