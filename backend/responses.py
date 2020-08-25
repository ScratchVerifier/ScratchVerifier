Null = type(None)

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
        for k in attrs['__annotations__']:
            slots.append(k)
        return type.__new__(cls, name, bases, {
            '__init__': __init__,
            'd': d,
            '__annotations__': attrs['__annotations__'],
            '__slots__': slots
        })
    def __instancecheck__(cls, instance):
        if isinstance(instance, dict):
            for k, v in cls.__annotations__.items():
                if not isinstance(instance[k], v):
                    return False
            return True
        else:
            return type.__instancecheck__(cls, instance)

class Verification(metaclass=Response):
    code: str
    username: str

class User(metaclass=Response):
    client_id: int
    token: str
    username: str

class Admin(metaclass=Response):
    admin: bool

class Log(metaclass=Response):
    log_id: int
    client_id: int
    username: str
    log_time: int
    log_type: int

class Ratelimit(metaclass=Response):
    username: int
    ratelimit: int

class PartialRatelimit(metaclass=Response):
    ratelimit: int

class Ban(metaclass=Response):
    username: str
    expiry: (int, Null)

class PartialBan(metaclass=Response):
    expiry: (int, Null)

class AuditLog(metaclass=Response):
    id: int
    username: str
    time: int
    type: int
    data: str

class Client(metaclass=Response):
    client_id: int
    token: str
    username: str
    ratelimit: int
    banned: bool
