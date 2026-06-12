class REnum(int):
    """
    Enum class similar to python's IntEnum but:
        - supports inheritance
        - Doesn't raise exception when the given value is not found in an enum class
    """
    @classmethod
    def get_name(cls, enum):
        """
        Search class attribues and base calss attributes to find the requested enum
        """
        for attr in vars(cls):
            if isinstance(cls.__dict__[attr], int) and cls.__dict__[attr] == enum:
                return f"{attr}"
        for base in cls.__bases__:
            for attr in vars(base):
                if isinstance(base.__dict__[attr], int) and base.__dict__[attr] == enum:
                    return f"{attr}"
        return "UNKNOWN ENUM!"

    @property
    def name(self):
        return self.get_name(self)

    def __str__(self):
        return f"{int(self)}"

    def __repr__(self):
        return f"<{self.name}: {int(self)}>"
