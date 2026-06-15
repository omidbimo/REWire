import logging
logger = logging.getLogger(__name__)

from .rw_enum import REnum
from .rw_packet import Packet

__all__ = [
    "SINT",
    "INT",
    "DINT",
    "LINT",
    "USINT",
    "BOOL",
    "UINT",
    "UDINT",
    "ULINT",
    "BYTE",
    "WORD",
    "DWORD",
    "LWORD",
    "STIME",
    "ITIME",
    "TIME",
    "DATE",
    "ARRAY",
    "BYTES",
    "STRING",
    "SHORT_STRING",
    "STRING2",
    "STRINGN",
    "STRINGI",
    "CLASS_ID_SEGMENT",
    "INSTANCE_ID_SEGMENT",
    "ATTRIBUTE_ID_SEGMENT",
    "MEMBER_ID_SEGMENT",
    "ELECTRONIC_KEY_SEGMENT",
    "ELECTRONIC_KEY_4",
    "ELECTRONIC_KEY_5",
    "PackedEPATH",
    "PaddedEPATH",
    "RequestPath",
]
class Dissect:
    def sint(bstream):
        return ( bstream[0], bstream[1:] )

    def usint(bstream):
        return ( bstream[0], bstream[1:] )

    def int(bstream):
        return int.from_bytes(bstream[0:2], byteorder="little"), bstream[2:]

    def uint(bstream):
        return int.from_bytes(bstream[0:2], byteorder="little"), bstream[2:]

    def dint(bstream):
        return int.from_bytes(bstream[0:4], byteorder="little"), bstream[4:]

    def udint(bstream):
        return int.from_bytes(bstream[0:4], byteorder="little"), bstream[4:]

    def ulint(bstream):
        return int.from_bytes(bstream[0:8], byteorder="little"), bstream[8:]

    def bool(bstream):
        return ( bstream[0], bstream[1:] )

    def byte(bstream):
        return ( bstream[0], bstream[1:] )

    def word(bstream):
        return int.from_bytes(bstream[0:2], byteorder="little"), bstream[2:]

    def dword(bstream):
        return int.from_bytes(bstream[0:4], byteorder="little"), bstream[4:]

    def str(n, bstream):
        return bstream[0:n].decode(encoding="utf-8"), bstream[n:]

    def bytes(n, bstream):
        return ( unpack_from("{}B".format(n), buf, 0), buf[calcsize("{}B".format(n)):] )

class Pack:
    def sint(val):
        return val.to_bytes(1, byteorder="little")

    def usint(val):
        return val.to_bytes(1, byteorder="little")

    def int(val):
        return val.to_bytes(2, byteorder="little")

    def uint(val):
        return val.to_bytes(2, byteorder="little")

    def dint(val):
        return val.to_bytes(4, byteorder="little")

    def udint(val):
        return val.to_bytes(4, byteorder="little")

    def ulint(val):
        return val.to_bytes(8, byteorder="little")

    def bool(val):
        return val.to_bytes(1)

    def byte(val):
        return val.to_bytes(1)

    def word(val):
        return val.to_bytes(2, byteorder="little")

    def dword(val):
        return val.to_bytes(4, byteorder="little")

    def str(string):
        return pack("{}s".format(len(string)), string)

class CIPDataType(REnum):
    UTIME         = 0xC0
    BOOL          = 0xC1
    SINT          = 0xC2
    INT           = 0xC3
    DINT          = 0xC4
    LINT          = 0xC5
    USINT         = 0xC6
    UINT          = 0xC7
    UDINT         = 0xC8
    ULINT         = 0xC9
    REAL          = 0xCA
    LREAL         = 0xCB
    STIME         = 0xCC
    DATE          = 0xCD
    TIME_OF_DAY   = 0xCE
    DATE_AND_TIME = 0xCF
    STRING        = 0xD0
    BYTE          = 0xD1
    WORD          = 0xD2
    DWORD         = 0xD3
    LWORD         = 0xD4
    STRING2       = 0xD5
    FTIME         = 0xD6
    LTIME         = 0xD7
    ITIME         = 0xD8
    STRINGN       = 0xD9
    SHORT_STRING  = 0xDA
    TIME          = 0xDB
    EPATH         = 0xDC
    ENGUNIT       = 0xDD
    STRINGI       = 0xDE
    NTIME         = 0xDF

class CIPInt(int):

    def __new__(cls, value=0):
        if not isinstance(value, int):
            raise TypeError(f"CIP type requires an int, got {type(value).__name__}")
        if not cls._min <= value <= cls._max:
            raise ValueError(f"CIP type value {value} out of range [{cls._min}, {cls._max}]")
        return super().__new__(cls, value)

    @classmethod
    def unpack(cls, bstream, error_on_excess=True):
        """
        Unpack bytes from bstream and convert them to the specified data format
        Returns the unpacked data
        """
        value, bstream = cls.dissect(bstream)

        if error_on_excess is True and len(bstream) > 0:
            raise Exception(
                f"Excess data in bstream! {cls.__name__} unpack requires a bstream of exactly {cls._len} bytes"
                f"but got {cls._len+len(bstream)} byte(s)."
            )
        return value

    @classmethod
    def check_min_len(cls, bstream):
        if len(bstream) < cls._len:
            raise Exception(
                f"Not enough data to unpack! {cls.__class__.__name__} dissect requires a bstream of exactly {cls._len}"
                f"bytes. {len(bstream)} bytes given."
            )


    def __add__(self, other):
        if not isinstance(other, type(self)) and not isinstance(other, int):
            raise Exception(f"Invalid operation between {type(self)} and {type(other)}.")
        return type(self)(int(self) + int(other))

    def __radd__(self, other):
        if not isinstance(other, type(self)) and not isinstance(other, int):
            raise Exception(f"Invalid operation between {type(self)} and {type(other)}.")
        return type(self)(int(other) + int(self))

    def __iadd__(self, other):
        if not isinstance(other, type(self)) and not isinstance(other, int):
            raise Exception(f"Invalid operation between {type(self)} and {type(other)}.")
        return type(self)(int(self) + int(other))

    @classmethod
    def __len__(cls):
        return cls._len

    def __str__(self):
        return f"{int(self)}"

    def __repr__(self):
        return f"{self.__class__.__name__}({int(self)})"


class SINT(CIPInt):
    _id = CIPDataType.SINT
    _min = -128
    _max = 127
    _len = 1

    def pack(self):
        return Pack.sint(self)

    @classmethod
    def dissect(cls, bstream):
        cls.check_min_len(bstream)
        value, bstream = Dissect.sint(bstream)
        return cls(value), bstream


class INT(CIPInt):
    _id = CIPDataType.INT
    _min = -32768
    _max = 32767
    _len = 2

    def pack(self):
        return Pack.int(self)

    @classmethod
    def dissect(cls, bstream):
        cls.check_min_len(bstream)
        value, bstream = Dissect.int(bstream)
        return cls(value), bstream


class DINT(CIPInt):
    _id = CIPDataType.DINT
    _min = -2147483648
    _max = 2147483647
    _len = 4

    def pack(self):
        return Pack.dint(self)

    @classmethod
    def dissect(cls, bstream):
        cls.check_min_len(bstream)
        value, bstream = Dissect.dint(bstream)
        return cls(value), bstream


class LINT(CIPInt):
    _id = CIPDataType.LINT
    _id = 0xD5
    _min = -9223372036854775808
    _max = 9223372036854775807
    _len = 8

    def pack(self):
        return  Pack.lint(self)

    @classmethod
    def dissect(cls, bstream):
        cls.check_min_len(bstream)
        value, bstream = Dissect.lint(bstream)
        return cls(value), bstream


class USINT(CIPInt):
    _id = CIPDataType.USINT
    _min = 0
    _max = 255
    _len = 1

    def pack(self):
        return  Pack.usint(self)

    @classmethod
    def dissect(cls, bstream):
        cls.check_min_len(bstream)
        value, bstream = Dissect.usint(bstream)
        return cls(value), bstream


class BOOL(USINT):
    _id = CIPDataType.BOOL
    _min = 0
    _max = 1
    _len = 1


class UINT(CIPInt):
    _id = CIPDataType.UINT
    _min = 0
    _max = 65535
    _len = 2

    def pack(self):
        return  Pack.uint(self)

    @classmethod
    def dissect(cls, bstream):
        cls.check_min_len(bstream)
        value, bstream = Dissect.uint(bstream)
        return cls(value), bstream


class UDINT(CIPInt):
    _id = CIPDataType.UDINT
    _min = 0
    _max = 4294967295
    _len = 4

    def pack(self):
        return  Pack.udint(self)

    @classmethod
    def dissect(cls, bstream):
        cls.check_min_len(bstream)
        value, bstream = Dissect.udint(bstream)
        return cls(value), bstream


class ULINT(CIPInt):
    _id = CIPDataType.ULINT
    _min = 0
    _max = 18446744073709551615
    _len = 8

    def pack(self):
        return Pack.ulint(self)

    @classmethod
    def dissect(cls, bstream):
        cls.check_min_len(bstream)
        value, bstream = Dissect.ulint(bstream)
        return cls(value), bstream


class BYTE(USINT):
    _id = CIPDataType.BYTE


class WORD(UINT):
    _id = CIPDataType.WORD


class DWORD(UDINT):
    _id = CIPDataType.DWORD


class LWORD(ULINT):
    _id = CIPDataType.LWORD


class STIME(ULINT):
    _id = CIPDataType.STIME


class ITIME(INT):
    _id = CIPDataType.ITIME


class TIME(DINT):
    _id = CIPDataType.TIME


class DATE():
    _id = CIPDataType.DATE
    #TODO

class ARRAY(list):

    def __init__(self, dtype: type=BYTE, items=None):
        self.dtype = dtype
        items = items or []
        self._validate_items(items)
        super().__init__(items)

    def _validate_item(self, item):
        if self.dtype and not isinstance(item, self.dtype):
            raise TypeError(f"CipARRAY expects {self.dtype.__name__}, got {type(item).__name__}")

    def _validate_items(self, items):
        for item in items:
            self._validate_item(item)

    # --- mutation methods ---
    def append(self, item):
        self._validate_item(item)
        super().append(item)

    def insert(self, index, item):
        self._validate_item(item)
        super().insert(index, item)

    def extend(self, items):
        self._validate_items(items)
        super().extend(items)

    def remove(self, item):
        self._validate_item(item)
        super().remove(item)

    def __setitem__(self, index, item):
        self._validate_item(item)
        super().__setitem__(index, item)

    def __iadd__(self, other):
        if isinstance(other, list):
            self.extend(other)
        elif isinstance(other, self.dtype):
            self.append(other)
        return self

    @classmethod
    def unpack(cls, bstream, error_on_excess=True):
        """
        Unpack bytes from bstream and convert them to the specified data format
        Returns the unpacked data
        """
        value, bstream = cls.dissect(bstream)

        if error_on_excess is True and len(bstream) > 0:
            raise Exception(
                f"Excess data in bstream! {cls.__name__} unpack requires a bstream of exactly {cls._len} bytes but got {cls._len+len(bstream)} byte(s)."
            )
        return value

    def pack(self):
        packed = bytes()
        for item in self:
            packed += item.pack()
        return packed

    @classmethod
    def dissect(cls, bstream, dtype, length=None):
        items = []

        if length is not None:
            for _ in range(length):
                item, bstream = dtype.dissect(bstream)
                items.append(item)
        else:  # No length is provided. Consume all available data
            while bstream:
                item, bstream = dtype.dissect(bstream)
                items.append(item)

        return cls(items), bstream

    def __str__(self):
        return "[" + ", ".join(str(item) for item in self) + "]"

    def __repr__(self):
        entries = "[" + ", ".join(f"{self.__class__.__name__}.{repr(item)}" for item in self) + "]"
        return f"{self.__class__.__name__}({entries})"


class BYTES(bytearray):
    def __init__(self, value=bytearray(), length=None):
        if isinstance(value, int):
            if length is None:
                value = value.to_bytes(length=(value.bit_length() + 7) // 8, byteorder="little")
            else:
                value = value.to_bytes(length, byteorder="little")
        elif length is not None:
            value = value[:length]
        super().__init__(value)

    def pack(self):
        return self

    @classmethod
    def unpack(cls, bstream, error_on_excess=True):
        """
        Unpack bytes from bstream and convert them to the specified data format
        Returns the unpacked data
        """
        value, bstream = cls.dissect(bstream)

        if error_on_excess is True and len(bstream) > 0:
            raise Exception(
                f"Excess data in bstream! {cls.__name__} unpack requires a bstream of exactly {cls._len} bytes but got {cls._len+len(bstream)} byte(s)."
            )
        return value

    @classmethod
    def dissect(cls, bstream, length=None):
        if length is None:
            length = len(bstream)
        return cls(bstream[:length]), bstream[length:]


class STRING(BYTES):
    _id = 0xD0

    def __init__(self, value=bytearray()):
        #if isinstance(value, str):
        #    value = value.to_bytes(byteorder="little")
        super().__init__(value)

    def pack(self):
        return self

    @classmethod
    def unpack(cls, bstream, error_on_excess=True):
        """
        Unpack bytes from bstream and convert them to the specified data format
        Returns the unpacked data
        """
        value, bstream = cls.dissect(bstream)

        if error_on_excess is True and len(bstream) > 0:
            raise Exception(
                f"Excess data in bstream! {cls.__name__} unpack requires a bstream of exactly {cls._len} bytes but got {cls._len+len(bstream)} byte(s)."
            )
        return value

    @classmethod
    def dissect(cls, bstream):
        return cls(bstream), bytes()

    def __str__(self):
        return "".join(f"{chr(octet)}" for octet in self)

    def __repr__(self):
        return "STRING(" + "".join(f"{chr(octet)}" for octet in self) + ")"


class STRING2(str):
    _id = 0xD5

    def __new__(cls, value):
        raise NotImplementedError("STRING2 is currently not supported")


class STRINGN(str):
    _id = 0xD9

    def __new__(cls, value):
        raise NotImplementedError("STRINGN is currently not supported")


class SHORT_STRING(str):
    _id = 0xDA
    _max_len = 255

    def __new__(cls, value=""):
        if not isinstance(value, str):
            raise TypeError(f"CIP type requires an str, got {type(value).__name__}")
        if len(value) > cls._max_len:
            raise ValueError(f"CipSHORT_STRING length {len(value)} exceeds max [{cls._max_len}]")
        return super().__new__(cls, value)

    def pack(self):
        return USINT(len(self)).pack() + self

    @classmethod
    def unpack(cls, bstream, error_on_excess=True):
        """
        Unpack bytes from bstream and convert them to the specified data format
        Returns the unpacked data
        """
        value, bstream = cls.dissect(bstream)

        if error_on_excess is True and len(bstream) > 0:
            raise Exception(
                f"Excess data in bstream! {cls.__name__} unpack requires a bstream of exactly {cls._len} bytes"
                f" but got {cls._len+len(bstream)} byte(s)."
            )
        return value

    @classmethod
    def dissect(cls, bstream):
        if len(bstream) == 0:
            raise Exception(f"Not enough data to unpack! {cls.__name__} dissect requires at least 1 byte to unpack."
                            f" {len(bstream)} bytes given.")

        str_len, bstream = USINT.dissect(bstream)
        if len(bstream) < str_len:
            raise Exception(f"Not enough data to unpack! {cls.__name__} dissect requires at least {str_len} byte(s) to"
                            f" unpack. {len(bstream)} bytes given.")

        value = "".join(f"{chr(octet)}" for octet in bstream[:str_len])
        return cls(value), bstream[str_len:]

    def __repr__(self):
        return f"{self.__class__.__name__}('{self}')"


class STRINGI(ARRAY):
    """
    CIP STRINGI — array of STRINGI.Entry instances,
    each representing the same string in a different language/encoding
    """

    _id = 0xDE

    def __init__(self, items=None):
        super().__init__(STRINGI.Entry, items or [])

    class Entry(Packet):
        """
        CIP STRINGI.Entry structure of International string and its metadata
            - string type is defined in encoding
            - language is a 3 letter ISO 639-2/T language Id
            - encoding is a one byte integer which determines the CIP STRING family
            - charset is a two bytes ISO 8859 symbolic table identifier
        """

        def __init__(self, string:str="", language="eng", encoding:int= SHORT_STRING._id, charset: int=4):

            if len(language) != 3:
                raise ValueError(f"language code must be 3 chars, got '{language}'")

            if isinstance(string, str):
                if encoding == STRING._id:  # 0xD0
                    string = STRING(string)
                elif encoding == STRING2._id:  # 0xD5
                    string = STRING2(string)
                elif encoding == STRINGN._id:  # 0xD9
                    string = STRINGN(string)
                elif encoding == SHORT_STRING._id:  # 0xDA
                    string = SHORT_STRING(string)
                else:
                    raise TypeError(f"String encoding must be 0xD0, 0xD5, 0xD9 or 0xDA, got {encoding}")

            self.string = string
            if isinstance(language, str):
                language = BYTES(language)
            self.language = language
            if isinstance(encoding, int):
                encoding = USINT(encoding)
            self.encoding = encoding
            if isinstance(charset, int):
                charset = UINT(charset)
            self.charset = charset

        def pack(self):
            packed = self.language.pack()
            packed += self.encoding.pack()
            packed += self.charset.pack()
            packed += self.string.pack()
            return packed

        @classmethod
        def dissect(cls, bstream):
            language, bstream = BYTES.dissect(bstream, 3)
            # String type
            encoding, bstream = USINT.dissect(bstream)
            # Char set
            charset, bstream = UINT.dissect(bstream)

            string = ""
            if encoding == 0xD0:
                string, bstream = STRING.dissect(bstream)
            elif encoding == 0xD5:
                string, bstream = STRING2.dissect(bstream)
            elif encoding == 0xD9:
                string, bstream = STRINGN.dissect(bstream)
            elif encoding == 0xDA:
                string, bstream = SHORT_STRING.dissect(bstream)
            else:
                raise Exception(f"Unknown string type 0x{encoding:02X} in STRINGI data")
            return cls(string, language, encoding, charset), bstream

        def __str__(self):
            return f" '{self.string}, '{self.language}', 0x{self.encoding:02X}, {self.charset}'"

        def __repr__(self):
            return f"{self.__class__.__name__}('{self.string}', '{self.language}', 0x{self.encoding:02X}, {self.charset})"

    def pack(self):
        packed = USINT(len(self)).pack()
        return packed + super(STRINGI, self).pack()

    @classmethod
    def dissect(cls, bstream):
        entry_count, bstream = USINT.dissect(bstream)
        return super().dissect(bstream, dtype=STRINGI.Entry, length=entry_count)


class CIP_SEGMENT(Packet):
    SEGMENT_TYPE_MASK = 0xE0
    SEGMENT_FORMAT_MASK = 0x1F

    SEGMENT_TYPE_PORT = 0
    SEGMENT_TYPE_LOGICAL = 1
    SEGMENT_TYPE_NETWORK = 2
    SEGMENT_TYPE_SYMBOLIC = 3
    SEGMENT_TYPE_DATA = 4

    def __init__(self, type_format=0, value=0):
        self.value = value
        self.type_format = type_format

    def pack(self, padded=False):
        raise NotImplementedError

    @classmethod
    def dissect(cls, bstream, padded=False):
        type_format, _ = USINT.dissect(bstream)
        segment_type = (type_format & cls.SEGMENT_TYPE_MASK) >> 5
        if segment_type == CIP_SEGMENT.SEGMENT_TYPE_LOGICAL:
            return LOGICAL_SEGMENT.dissect(bstream, padded)
        else:
            raise Exception(f"Unexpected segment type {segment_type} when unpacking {cls.__name__}!")

    def __len__(self):
        return len(self.pack())

    def __str__(self):
        return " ".join(f"{octet:02X}" for octet in self.pack())

    def __repr__(self):
        return f"{self.__class__.__name__}(type_format=0x{self.type_format:01X}, value=0x{self.value:01X})"


class LOGICAL_SEGMENT(CIP_SEGMENT):
    LOGICAL_TYPE_MASK = 0x1C
    LOGICAL_FORMAT_MASK = 0x03

    FORMAT_8_BIT = 0
    FORMAT_16_BIT = 1
    FORMAT_32_BIT = 2
    FORMAT_8_BIT_SERVICE_ID = 0
    FORMAT_ELECTRONIC_KEY = 0

    TYPE_CLASS_ID = 0
    TYPE_INSTANCE_ID = 1
    TYPE_MEMBER_ID = 2
    TYPE_CONNECTION_POINT = 3
    TYPE_ATTRIBUTE_ID = 4
    TYPE_SPECIAL = 5
    TYPE_SERVICE_ID = 6
    TYPE_EXTENDED_LOGICAL = 7

    EXTENDED_TYPE_ARRAY_INDEX = 1
    EXTENDED_TYPE_INDIRECT_ARRAY_INDEX = 2
    EXTENDED_TYPE_BIT_INDEX = 3
    EXTENDED_TYPE_INDIRECT_BIT_INDEX = 4
    EXTENDED_TYPE_STRUCTURE_MEMBER_NUMBER = 5
    EXTENDED_TYPE_STRUCTURE_MEMBER_HANDLE = 6

    def __init__(self, value=0, logical_type=0, logical_format=0):
        if logical_type > 7:
            raise Exception(f"Invalid logical type! {logical_type} is larger than max. logical type.")
        if logical_format > LOGICAL_SEGMENT.FORMAT_32_BIT:
            raise Exception(f"{logical_format} is an invalid Logical Format!")
        if (
            (logical_format == LOGICAL_SEGMENT.FORMAT_8_BIT and value > USINT._max)
            or (logical_format == LOGICAL_SEGMENT.FORMAT_16_BIT and value > UINT._max)
            or (logical_format == LOGICAL_SEGMENT.FORMAT_32_BIT and value > UDINT._max)
        ):
            raise Exception(f"Logical format {logical_format} can not handle given value {value}!")
        super().__init__(CIP_SEGMENT.SEGMENT_TYPE_LOGICAL << 5 | logical_type << 2 | logical_format, value)

    def pack(self, padded=False):
        packed = USINT(self.type_format).pack()
        logical_format = self.type_format & self.LOGICAL_FORMAT_MASK
        if logical_format == LOGICAL_SEGMENT.FORMAT_8_BIT:
            packed += USINT(self.value).pack()
        elif logical_format == LOGICAL_SEGMENT.FORMAT_16_BIT:
            if padded is True:
                packed += USINT(0).pack()
            packed += UINT(self.value).pack()
        elif logical_format == LOGICAL_SEGMENT.FORMAT_32_BIT:
            if padded is True:
                packed += USINT(0).pack()
            packed += UDINT(self.value).pack()
        else:
            raise Exception("Unexpected Logical Format!")
        return packed

    @classmethod
    def dissect(cls, bstream, padded=False):
        type_format, _ = USINT.dissect(bstream) # Do not consume the byte yet
        if ((type_format & cls.LOGICAL_TYPE_MASK) >> 2) == cls.TYPE_SPECIAL:
            return ELECTRONIC_KEY_SEGMENT.dissect(bstream)

        type_format, bstream = USINT.dissect(bstream)

        logical_type = (type_format & LOGICAL_SEGMENT.LOGICAL_TYPE_MASK) >> 2

        if (
            logical_type != cls.TYPE_CLASS_ID
            and logical_type != cls.TYPE_INSTANCE_ID
            and logical_type != cls.TYPE_MEMBER_ID
            and logical_type != cls.TYPE_CONNECTION_POINT
            and logical_type != cls.TYPE_ATTRIBUTE_ID
        ):
            raise Exception(f"Unexpected Logical Segment type: {logical_type}")

        logical_format = type_format & LOGICAL_SEGMENT.LOGICAL_FORMAT_MASK
        if logical_format == LOGICAL_SEGMENT.FORMAT_8_BIT:
            value, bstream = USINT.dissect(bstream)
        if logical_format == LOGICAL_SEGMENT.FORMAT_16_BIT:
            if padded is True:
                _, bstream = USINT.dissect(bstream)
            value, bstream = UINT.dissect(bstream)
        if logical_format == LOGICAL_SEGMENT.FORMAT_32_BIT:
            if padded is True:
                _, bstream = USINT.dissect(bstream)
            value, bstream = UDINT.dissect(bstream)

        if logical_type == cls.TYPE_CLASS_ID:
            return CLASS_ID_SEGMENT(value, logical_format), bstream
        if logical_type == cls.TYPE_INSTANCE_ID:
            return INSTANCE_ID_SEGMENT(value, logical_format), bstream
        if logical_type == cls.TYPE_MEMBER_ID:
            return MEMBER_ID_SEGMENT(value, logical_format), bstream
        if logical_type == cls.TYPE_CONNECTION_POINT:
            return CONNECTION_POINT_SEGMENT(value, logical_format), bstream
        if logical_type == cls.TYPE_ATTRIBUTE_ID:
            return ATTRIBUTE_ID_SEGMENT(value, logical_format), bstream

    """
    def __repr__(self):
        return f"{self.__class__.__name__}(value=0x{self.value:01X}, logical_type=0x{self.logical_type:01X}, logical_format=0x{self.logical_format:01X})"
    """


class CLASS_ID_SEGMENT(LOGICAL_SEGMENT):
    def __init__(self, value=0, logical_format=None):
        if logical_format is None:
            if value <= 0xFF:
                logical_format = LOGICAL_SEGMENT.FORMAT_8_BIT
            elif value <= 0xFFFF:
                logical_format = LOGICAL_SEGMENT.FORMAT_16_BIT
            elif value <= 0xFFFFFFFF:
                logical_format = LOGICAL_SEGMENT.FORMAT_32_BIT
            else:
                raise Exception(f"Value larger than 32-bit! {value}")

        super().__init__(value, LOGICAL_SEGMENT.TYPE_CLASS_ID, logical_format)

    @classmethod
    def dissect(cls, bstream, padded=False):
        type_format, _ = USINT.dissect(bstream) # Do not consume the byte yet
        logical_type = (type_format & LOGICAL_SEGMENT.LOGICAL_TYPE_MASK) >> 2
        if logical_type != cls.TYPE_CLASS_ID:
            raise Exception(f"Unexpected segment type {logical_type} when unpacking {cls.__name__}!")

        return super(CLASS_ID_SEGMENT, cls).dissect(bstream, padded)

    def __repr__(self):
        return f"{self.__class__.__name__}(value=0x{self.value:01X}, logical_format=0x{(self.type_format & LOGICAL_SEGMENT.LOGICAL_FORMAT_MASK):01X})"


class INSTANCE_ID_SEGMENT(LOGICAL_SEGMENT):
    def __init__(self, value=0, logical_format=None):
        if logical_format is None:
            if value <= 0xFF:
                logical_format = LOGICAL_SEGMENT.FORMAT_8_BIT
            elif value <= 0xFFFF:
                logical_format = LOGICAL_SEGMENT.FORMAT_16_BIT
            elif value <= 0xFFFFFFFF:
                logical_format = LOGICAL_SEGMENT.FORMAT_32_BIT
            else:
                raise Exception(f"Value larger than 32-bit! {value}")

        super(INSTANCE_ID_SEGMENT, self).__init__(value, LOGICAL_SEGMENT.TYPE_INSTANCE_ID, logical_format)

    @classmethod
    def dissect(cls, bstream, padded=False):
        type_format, _ = USINT.dissect(bstream) # Do not consume the byte yet
        logical_type = (type_format & LOGICAL_SEGMENT.LOGICAL_TYPE_MASK) >> 2
        if logical_type != cls.TYPE_INSTANCE_ID:
            raise Exception(f"Unexpected segment type {logical_type} when unpacking {cls.__name__}!")

        return super(INSTANCE_ID_SEGMENT, cls).dissect(bstream, padded)

    def __repr__(self):
        return f"{self.__class__.__name__}(value=0x{self.value:01X}, logical_format=0x{(self.type_format & LOGICAL_SEGMENT.LOGICAL_FORMAT_MASK):01X})"


class ATTRIBUTE_ID_SEGMENT(LOGICAL_SEGMENT):
    def __init__(self, value=0, logical_format=None):
        if logical_format is None:
            if value <= 0xFF:
                logical_format = LOGICAL_SEGMENT.FORMAT_8_BIT
            elif value <= 0xFFFF:
                logical_format = LOGICAL_SEGMENT.FORMAT_16_BIT
            elif value <= 0xFFFFFFFF:
                logical_format = LOGICAL_SEGMENT.FORMAT_32_BIT
            else:
                raise Exception(f"Value larger than 32-bit! {value}")

        super(ATTRIBUTE_ID_SEGMENT, self).__init__(value, LOGICAL_SEGMENT.TYPE_ATTRIBUTE_ID, logical_format)

    @classmethod
    def dissect(cls, bstream, padded=False):
        type_format, _ = USINT.dissect(bstream) # Do not consume the byte yet
        logical_type = (type_format & LOGICAL_SEGMENT.LOGICAL_TYPE_MASK) >> 2
        if logical_type != cls.TYPE_ATTRIBUTE_ID:
            raise Exception(f"Unexpected segment type {logical_type} when unpacking {cls.__name__}!")

        return super(ATTRIBUTE_ID_SEGMENT, cls).dissect(bstream, padded)

    def __repr__(self):
        return f"{self.__class__.__name__}(value=0x{self.value:01X}, logical_format=0x{(self.type_format & LOGICAL_SEGMENT.LOGICAL_FORMAT_MASK):01X})"


class MEMBER_ID_SEGMENT(LOGICAL_SEGMENT):
    def __init__(self, value=0, logical_format=None):
        if logical_format is None:
            if value <= 0xFF:
                logical_format = LOGICAL_SEGMENT.FORMAT_8_BIT
            elif value <= 0xFFFF:
                logical_format = LOGICAL_SEGMENT.FORMAT_16_BIT
            elif value <= 0xFFFFFFFF:
                logical_format = LOGICAL_SEGMENT.FORMAT_32_BIT
            else:
                raise Exception("Value larger than 32-bit! {}".format(value))

        super(MEMBER_ID_SEGMENT, self).__init__(value, LOGICAL_SEGMENT.TYPE_MEMBER_ID, logical_format)

    @classmethod
    def dissect(cls, bstream, padded=False):
        type_format, _ = USINT.dissect(bstream) # Do not consume the byte yet
        logical_type = (type_format & LOGICAL_SEGMENT.LOGICAL_TYPE_MASK) >> 2
        if logical_type != cls.TYPE_MEMBER_ID:
            raise Exception("Unexpected segment type {} when unpacking {}!".format(logical_type, cls.__name__))

        return super(MEMBER_ID_SEGMENT, cls).dissect(bstream, padded)

    def __repr__(self):
        return f"{self.__class__.__name__}(value=0x{self.value:01X}, logical_format=0x{(self.type_format & LOGICAL_SEGMENT.LOGICAL_FORMAT_MASK):01X})"


class CONNECTION_POINT_SEGMENT(LOGICAL_SEGMENT):
    def __init__(self, value=0, logical_format=None):
        if logical_format is None:
            if value <= 0xFF:
                logical_format = LOGICAL_SEGMENT.FORMAT_8_BIT
            elif value <= 0xFFFF:
                logical_format = LOGICAL_SEGMENT.FORMAT_16_BIT
            elif value <= 0xFFFFFFFF:
                logical_format = LOGICAL_SEGMENT.FORMAT_32_BIT
            else:
                raise Exception("Value larger than 32-bit! {}".format(value))

        super(CONNECTION_POINT_SEGMENT, self).__init__(value, LOGICAL_SEGMENT.TYPE_CONNECTION_POINT, logical_format)

    @classmethod
    def dissect(cls, bstream, padded=False):
        type_format, _ = USINT.dissect(bstream) # Do not consume the byte yet
        logical_type = (type_format & LOGICAL_SEGMENT.LOGICAL_TYPE_MASK) >> 2
        if logical_type != cls.TYPE_CONNECTION_POINT:
            raise Exception("Unexpected segment type {} when unpacking {}!".format(logical_type, cls.__name__))

        return super(CONNECTION_POINT_SEGMENT, cls).dissect(bstream, padded)

    def __repr__(self):
        return f"{self.__class__.__name__}(value=0x{self.value:01X}, logical_format=0x{(self.type_format & LOGICAL_SEGMENT.LOGICAL_FORMAT_MASK):01X})"


class ELECTRONIC_KEY_SEGMENT(LOGICAL_SEGMENT):
    FORMAT_REQUIRED = 4
    FORMAT_OPTIONAL = 5

    def __init__(self, key_format, vendor_id=0, device_type=0, product_code=0, major_rev=0, minor_rev=0, serial_number=0):
        if key_format != ELECTRONIC_KEY_SEGMENT.FORMAT_REQUIRED and key_format != ELECTRONIC_KEY_SEGMENT.FORMAT_OPTIONAL:
            raise Exception("Unknown Electronic Key format {}!".format(key_format))
        self.key_format = USINT(key_format)
        self.vendor_id = UINT(vendor_id)
        self.device_type = UINT(device_type)
        self.product_code = UINT(product_code)
        self.major_rev = BYTE(major_rev)
        self.minor_rev = BYTE(minor_rev)
        self.serial_number = UDINT(serial_number)

    def pack(self, padded=False):
        packed = USINT((CIP_SEGMENT.SEGMENT_TYPE_LOGICAL << 5) | (LOGICAL_SEGMENT.TYPE_SPECIAL << 2) | LOGICAL_SEGMENT.FORMAT_ELECTRONIC_KEY).pack()
        packed += self.key_format.pack()
        packed += self.vendor_id.pack()
        packed += self.device_type.pack()
        packed += self.product_code.pack()
        packed += self.major_rev.pack() + self.minor_rev.pack()
        return packed

    @classmethod
    def dissect(cls, bstream):
        try:
            return ELECTRONIC_KEY_4.dissect(bstream)
        except TypeError:
            pass

        try:
            return ELECTRONIC_KEY_5.dissect(bstream)
        except TypeError:
            pass

        raise TypeError("Unable to unpack an Electronic Key from bstream!")

    def __len__(self):
        return len(self.pack())


class ELECTRONIC_KEY_4(ELECTRONIC_KEY_SEGMENT):
    def __init__(self, vendor_id, device_type, product_code, major_rev, minor_rev):
        super(ELECTRONIC_KEY_4, self).__init__(ELECTRONIC_KEY_SEGMENT.FORMAT_REQUIRED, vendor_id, device_type, product_code, major_rev, minor_rev)

    @classmethod
    def dissect(cls, bstream):
        segment_id, bstream = USINT.dissect(bstream)
        if ((segment_id & LOGICAL_SEGMENT.LOGICAL_TYPE_MASK) >> 2) != LOGICAL_SEGMENT.TYPE_SPECIAL or (segment_id & LOGICAL_SEGMENT.LOGICAL_FORMAT_MASK) != 0:
            raise TypeError(f"Unexpected segment type {segment_id} when unpacking {cls.__name__}!")

        key_format, bstream = USINT.dissect(bstream)
        if key_format != ELECTRONIC_KEY_SEGMENT.FORMAT_REQUIRED:
            raise ValueError(f"Unexpected Electronic Format! expected:0x04, got:0x{key_format:02X}")

        vendor_id, bstream = UINT.dissect(bstream)
        device_type, bstream = UINT.dissect(bstream)
        product_code, bstream = UINT.dissect(bstream)
        major_rev, bstream = BYTE.dissect(bstream)
        minor_rev, bstream = BYTE.dissect(bstream)
        return cls(vendor_id, device_type, product_code, major_rev, minor_rev), bstream

    def __repr__(self):
        return (
            f"{self.__class__.__name__}(key_format={self.key_format}, "
            f"vendor_id={self.vendor_id}, "
            f"device_type={self.device_type}, "
            f"product_code={self.product_code}, "
            f"major_rev ={self.major_rev}, "
            f"minor_rev={self.minor_rev})"
        )


class ELECTRONIC_KEY_5(ELECTRONIC_KEY_SEGMENT):
    def __init__(self, vendor_id, device_type, product_code, major_rev, minor_rev, serial_number):
        super().__init__(ELECTRONIC_KEY_SEGMENT.FORMAT_OPTIONAL, vendor_id, device_type, product_code, major_rev, minor_rev, serial_number)

    def pack(self, padded=False):
        return super().pack() + UDINT(self.serial_number).pack()

    @classmethod
    def dissect(cls, bstream):
        segment_id, bstream = USINT.dissect(bstream)
        if ((segment_id & LOGICAL_SEGMENT.LOGICAL_TYPE_MASK) >> 2) != LOGICAL_SEGMENT.TYPE_SPECIAL or (segment_id & LOGICAL_SEGMENT.LOGICAL_FORMAT_MASK) != 0:
            raise TypeError(f"Unexpected segment type {segment_id} when unpacking {cls.__name__}!")

        key_format, bstream = USINT.dissect(bstream)
        if key_format != ELECTRONIC_KEY_SEGMENT.FORMAT_OPTIONAL:
            raise ValueError(f"Unexpected Electronic Format! expected:0x04, got:0x{key_format:02X}")

        vendor_id, bstream = UINT.dissect(bstream)
        device_type, bstream = UINT.dissect(bstream)
        product_code, bstream = UINT.dissect(bstream)
        major_rev, bstream = BYTE.dissect(bstream)
        minor_rev, bstream = BYTE.dissect(bstream)
        serial_number, bstream = UDINT.dissect(bstream)
        return cls(vendor_id, device_type, product_code, major_rev, minor_rev, serial_number), bstream

    def __repr__(self):
        return (
            f"{self.__class__.__name__}(key_format={self.key_format}, "
            f"vendor_id={self.vendor_id}, "
            f"device_type={self.device_type}, "
            f"product_code={self.product_code}, "
            f"major_rev ={self.major_rev}, "
            f"minor_rev={self.minor_rev}, "
            f"serial_number={self.serial_number})"
        )


class EPATH(ARRAY):
    _id = CIPDataType.EPATH

    def __init__(self, segments):
        super().__init__(dtype=CIP_SEGMENT, items=segments)

    def _validate_segments(self, segments):
        for item in segments:
            if not isinstance(item, CIP_SEGMENT):
                raise Exception(f"EPATH expects elements of CIP_SEGMENT, got {type(item)}")

    def pack(self):
        packed = USINT(self.__len__()).pack()
        for segment in self:
            packed += segment.pack()
        return  packed


class PackedEPATH(EPATH):

    def __init__(self, segments=None):
        super().__init__(segments or [])

    @classmethod
    def dissect(cls, bstream):
        path_size, bstream = USINT.dissect(bstream)
        path = cls()

        path_size *= 2
        while path_size > 0:
            segment, bstream = CIP_SEGMENT.dissect(bstream, padded=False)
            path += segment
            path_size -= len(segment)

        return path, bstream

    def __len__(self):
        """
        EPATH len requires special handling.
        """
        length = 0
        for segment in self:
            length += len(segment.pack())
            assert length % 2 == 0
        return length // 2  # Word size of the path


class PaddedEPATH(EPATH):
    def __init__(self, segments=None):
        super().__init__(segments or [])

    def pack(self):
        packed = USINT(self.__len__()).pack()
        for segment in self:
            packed += segment.pack(padded=True)
        return packed

    @classmethod
    def dissect(cls, bstream):
        path_size, bstream = USINT.dissect(bstream)
        path = cls()

        path_size *= 2
        while path_size > 0:
            segment, bstream = CIP_SEGMENT.dissect(bstream, padded=True)
            path += segment
            path_size -= len(segment.pack(padded=True))

        return path, bstream

    def __len__(self):
        """
        EPATH len requires special handling.
        """
        length = 0
        for segment in self:
            # The segment supports no padding concept. Therefore to get it's length it must be packed with padding.
            length += len(segment.pack(padded=True))
            assert length % 2 == 0
        return length // 2  # Word size of the path

    def __str__(self):
        return " ".join(" ".join(f"{octet:02X}" for octet in segment.pack(padded=True)) for segment in self)


class RequestPath(PaddedEPATH):
    """
    [Electronic key segment]
    Application Path
    """
    def __init__(self, class_id: int=None, instance_id: int=None, attribute_id: int=None,
            member_id=None, ekey: ELECTRONIC_KEY_SEGMENT=None):
        super(RequestPath, self).__init__()
        if ekey is not None and isinstance(ekey, ELECTRONIC_KEY_SEGMENT):
            self += ekey
        if class_id is not None:
            self += CLASS_ID_SEGMENT(class_id)
        if instance_id is not None:
            self += INSTANCE_ID_SEGMENT(instance_id)
        if attribute_id is not None:
            self += ATTRIBUTE_ID_SEGMENT(attribute_id)
        if member_id is not None:
            self += MEMBER_ID_SEGMENT(member_id)

    def dissect(self, bstream):
        bstream = super(RequestPath, self).dissect(bstream)
        for segment in self._segments:
            if isinstance(segment, ELECTRONIC_KEY_SEGMENT) and self._segments.index(segment) != 0:
                logger.warning("Malformed Request PATH! An electronic key segment has to be the first segment of request path.")
            #TODO: more checking

    @property
    def class_id(self):
        for segment in self._segments:
            if isinstance(segment, CLASS_ID_SEGMENT):
                return segment._value
        return None

    @property
    def instance_id(self):
        for segment in self._segments:
            if isinstance(segment, INSTANCE_ID_SEGMENT):
                return segment._value
        return None

    @property
    def attribute_id(self):
        for segment in self._segments:
            if isinstance(segment, ATTRIBUTE_ID_SEGMENT):
                return segment._value
        return None

    @property
    def member_id(self):
        for segment in self._segments:
            if isinstance(segment, MEMBER_ID_SEGMENT):
                return segment._value
        return None

    @property
    def class_segment(self):
        for segment in self._segments:
            if isinstance(segment, CLASS_ID_SEGMENT):
                return segment
        return None

    @property
    def instance_segment(self):
        for segment in self._segments:
            if isinstance(segment, INSTANCE_ID_SEGMENT):
                return segment
        return None

    @property
    def attribute_segment(self):
        for segment in self._segments:
            if isinstance(segment, ATTRIBUTE_ID_SEGMENT):
                return segment
        return None

    @property
    def member_segment(self):
        for segment in self._segments:
            if isinstance(segment, MEMBER_ID_SEGMENT):
                return segment
        return None

    @property
    def key_segment(self):
        for segment in self._segments:
            if isinstance(segment, ELECTRONIC_KEY_SEGMENT):
                return segment
        return None


class ApplicationPath(EPATH):

    @property
    def class_id(self):
        for segment in self._segments:
            if isinstance(segment, CLASS_ID_SEGMENT):
                return segment._value
        return None

    @property
    def instance_id(self):
        for segment in self._segments:
            if isinstance(segment, INSTANCE_ID_SEGMENT):
                return segment._value
        return None

    @property
    def attribute_id(self):
        for segment in self._segments:
            if isinstance(segment, ATTRIBUTE_ID_SEGMENT):
                return segment._value
        return None

    @property
    def member_id(self):
        for segment in self._segments:
            if isinstance(segment, MEMBER_ID_SEGMENT):
                return segment._value
        return None

    @property
    def class_segment(self):
        for segment in self._segments:
            if isinstance(segment, CLASS_ID_SEGMENT):
                return segment
        return None

    @property
    def instance_segment(self):
        for segment in self._segments:
            if isinstance(segment, INSTANCE_ID_SEGMENT):
                return segment
        return None

    @property
    def attribute_segment(self):
        for segment in self._segments:
            if isinstance(segment, ATTRIBUTE_ID_SEGMENT):
                return segment
        return None

    @property
    def member_segment(self):
        for segment in self._segments:
            if isinstance(segment, MEMBER_ID_SEGMENT):
                return segment
        return None
