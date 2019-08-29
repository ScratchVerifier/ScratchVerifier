import json

class Response(type):
    def __new__(cls, name, bases, attrs):
        def __init__(self, **kwargs):
            for k in self.__slots__:
                if k.startswith('_'):
                    continue
                setattr(self, k, kwargs.get(k, None))
        def d(self):
            return {
                k: getattr(self, k)
                for k in self.__slots__
                if not k.startswith('_')
            }
        slots = []
        for k in attrs:
            slots.append(k)
        return type.__new__(cls, name, bases, {
            '__init__': __init__,
            'd': d,
            '__slots__': slots
        })

class Verification(metaclass=Response):
    code = str
    username = str

class Session(metaclass=Response):
    session = int

class User(metaclass=Response):
    client_id = int
    token = str
    username = str

class Log(metaclass=Response):
    log_id = int
    client_id = int
    username = str
    log_time = int
    log_type = int
