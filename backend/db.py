import time
from secrets import token_bytes, token_hex, randbits
from hashlib import sha256
import aiosqlite as sql

DATABASE_FILENAME = 'scratchverifier.db'
USERS_API = 'https://api.scratch.mit.edu/users/{}'

class Database:
    def __init__(self, session):
        loop = asyncio.get_event_loop()
        self.dbw = sql.connect(DATABASE_FILENAME)
        self.dbw.row_factory = sql.Row
        self.db = loop.run_until_complete(self.dbw.cursor())
        self.session = session

    async def close(self):
        await self.db.commit()
        await self.dbw.close()

    ### TABLE: clients ###

    async def client_matches(self, client_id, token):
        async with self.db.execute('SELECT client_id FROM clients \
WHERE client_id=? AND token=?', (client_id, token)):
            if (await self.db.fetchone()):
                return True
            return False

    ### TABLE: clients and sessions ###

    async def username_from_session(self, session_id):
        async with self.db.execute('SELECT username FROM sessions \
WHERE session_id=?', (session_id,)):
            row = await self.db.fetchone()
        if row is None:
            return None

    async def new_client(self, session_id):
        username = self.username_from_session(session_id)
        if username is None:
            return None
        async with self.session.get(USERS_API.format(username)) as resp:
            assert resp.status == 200
            data = await resp.json()
        client_id = data['id']
        token = token_hex(32)
        await self.db.execute('INSERT INTO clients (client_id, token, \
username) VALUES (?, ?, ?)', (client_id, token, username))
        return {'client_id': client_id, 'token': token, 'username': username}

    async def get_client(self, session_id):
        username = self.username_from_session(session_id)
        if username is None:
            return None
        async with self.db.execute('SELECT * FROM clients \
WHERE username=?', (username,)):
            row = await self.db.fetchone()
        if row is None:
            return None
        return dict(row)

    async def reset_token(self, session_id):
        username = self.username_from_session(session_id)
        if username is None:
            return
        await self.db.execute('UPDATE clients SET token=? \
WHERE username=?', (token_hex(32), username))

    async def del_client(self, session_id):
        username = self.username_from_session(session_id)
        if username is None:
            return
        await self.db.execute('DELETE FROM clients \
WHERE username=?', (username,))

    ### TABLE: sessions ###

    async def new_session(self, username):
        while 1:
            session_id = randbits(64)
            async with self.db.execute('SELECT session_id FROM sessions \
WHERE session_id=?', (session_id,)):
                if (await self.db.fetchone()) is None:
                    break
        await self.db.execute('INSERT INTO sessions (session_id, expiry, \
username) VALUES (?, ?, ?)', (
            session_id,
            int(time.time),
            username
        ))
        return session_id

    async def get_expired(self, session_id):
        async with self.db.execute('SELECT expiry FROM sessions \
WHERE session_id=?', (session_id,)):
            expiry = (await self.db.fetchone())[0]
        if time.time() > expiry:
            await self.db.execute('DELETE FROM sessions \
WHERE session_id=?', (session_id,))
            return True
        return False

    ### TABLE: usage ###

    async def start_verification(self, client_id, username):
        code = sha256(
            str(client_id).encode()
            + str(time.time()).encode()
            + username.encode()
            + token_bytes()
        )
        await self.db.execute('INSERT INTO usage (client_id, code, username, \
expiry) VALUES (?, ?, ?, ?)', (client_id, code, username,
                               int(time.time() + 1800)))
        return code

    async def get_code(self, client_id, username):
        async with self.db.execute('SELECT code, expiry FROM usage \
WHERE client_id=? AND username=?', (client_id, username)):
            row = await self.db.fetchone()
        if row is None:
            return None
        if time.time() > row['expiry']:
            await self.end_verification(client_id, username)
            return None
        return row['code']

    async def end_verification(self, client_id, username):
        await self.db.execute('DELETE FROM usage WHERE client_id=? \
AND username=?', (client_id, username))
