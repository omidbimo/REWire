class Enum_():

    def name(self, enum):
        for attr in vars(self.__class__):
            if isinstance(self.__class__.__dict__[attr], int) and self.__class__.__dict__[attr] == enum: return '{}'.format(attr)
        for base in self.__class__.__bases__:
            for attr in vars(base):
                if isinstance(base.__dict__[attr], int) and base.__dict__[attr] == enum: return '{}'.format(attr)
        return ''

    @classmethod
    def name(cls, enum):
        for attr in vars(cls):
            if isinstance(cls.__dict__[attr], int) and cls.__dict__[attr] == enum: return '{}'.format(attr)
        for base in cls.__bases__:
            for attr in vars(base):
                if isinstance(base.__dict__[attr], int) and base.__dict__[attr] == enum: return '{}'.format(attr)
        return ''