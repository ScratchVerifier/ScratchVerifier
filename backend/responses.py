import re

DEFAULT_PORT = 8888
COMMENTS_API = 'https://scratch.mit.edu/site-api/comments/user/{}/\
?page=1&salt={}'
USERNAME_REGEX = re.compile('^[A-Za-z0-9_-]{3,20}$')
COMMENTS_REGEX = re.compile(r"""<div id="comments-\d+" class="comment +" data-comment-id="\d+">.*?<div class="actions-wrap">.*?<div class="name">\s+<a href="/users/([_a-zA-Z0-9-]+)">\1</a>\s+</div>\s+<div class="content">(.*?)</div>""", re.S)
LIMIT_PER_TIME = 60 # in seconds
DEFAULT_LOG_LIMIT = 100 # how many log entries to show if limit is unspecified
MAX_LOG_LIMIT = 500 # how many /usage logs are allowed to show at once
DEFAULT_RATELIMIT = 30 # max requests per LIMIT_PER_TIME
TOKEN_CENSOR_LEN = 8 # how many characters to show in admin-viewed tokens
HEADER_FORMAT = 'left={}, resets={}, to={}'

DATABASE_FILENAME = 'scratchverifier.db'
USERS_API = 'https://api.scratch.mit.edu/users/{}'
VERIFY_EXPIRY = 1800 # 30 minutes
SESSION_EXPIRY = 31540000 # 1 year in seconds

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
    username: str
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
    ratelimit: (int, Null)
