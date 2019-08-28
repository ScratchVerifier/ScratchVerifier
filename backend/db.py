import os
import time
from secrets import token_bytes, token_hex, randbits
from hashlib import sha256
import asyncio
import aiosqlite as sql

DATABASE_FILENAME = 'scratchverifier.db'
USERS_API = 'https://api.scratch.mit.edu/users/{}'

class Database:
    def __init__(self, session):
        loop = asyncio.get_event_loop()
        self.dbw = loop.run_until_complete(sql.connect(DATABASE_FILENAME))
        self.dbw.row_factory = sql.Row
        self.db = loop.run_until_complete(self.dbw.cursor())
        with open(os.path.join(os.path.dirname(__file__), 'sql',
                               'startup.sql')) as startup:
            loop.run_until_complete(self.db.executescript(startup.read()))
        self.session = session

    async def close(self):
        await self.dbw.commit()
        await self.dbw.close()

    ### TABLE: clients ###

    async def client_matches(self, client_id, token):
        await self.db.execute('SELECT client_id FROM scratchverifier_clients \
WHERE client_id=? AND token=?', (client_id, token))
        if (await self.db.fetchone()):
            return True
        return False

    ### TABLE: clients and sessions ###

    async def username_from_session(self, session_id):
        await self.db.execute('SELECT username FROM scratchverifier_sessions \
WHERE session_id=?', (session_id,))
        row = await self.db.fetchone()
        if row is None:
            return None
        return row[0]

    async def new_client(self, session_id):
        username = await self.username_from_session(session_id)
        if username is None:
            return None
        async with self.session.get(USERS_API.format(username)) as resp:
            assert resp.status == 200
            data = await resp.json()
        client_id = data['id']
        token = token_hex(32)
        await self.db.execute('INSERT INTO scratchverifier_clients (client_id, \
token, username) VALUES (?, ?, ?)', (client_id, token, username))
        return {'client_id': client_id, 'token': token, 'username': username}

    async def get_client(self, session_id):
        username = await self.username_from_session(session_id)
        if username is None:
            return None
        await self.db.execute('SELECT * FROM scratchverifier_clients \
WHERE username=?', (username,))
        row = await self.db.fetchone()
        if row is None:
            return None
        return dict(row)

    async def reset_token(self, session_id):
        username = await self.username_from_session(session_id)
        if username is None:
            return
        await self.db.execute('UPDATE scratchverifier_clients SET token=? \
WHERE username=?', (token_hex(32), username))

    async def del_client(self, session_id):
        username = await self.username_from_session(session_id)
        if username is None:
            return
        await self.db.execute('DELETE FROM scratchverifier_clients \
WHERE username=?', (username,))

    ### TABLE: sessions ###

    async def new_session(self, username):
        while 1:
            session_id = randbits(32)
            await self.db.execute('SELECT session_id FROM \
scratchverifier_sessions WHERE session_id=?', (session_id,))
            if (await self.db.fetchone()) is None:
                break
        await self.db.execute('INSERT INTO scratchverifier_sessions \
(session_id, expiry, username) VALUES (?, ?, ?)', (
            session_id,
            int(time.time()) + 31540000, # 1 year in seconds
            username
        ))
        return session_id

    async def get_expired(self, session_id):
        await self.db.execute('SELECT expiry FROM scratchverifier_sessions \
WHERE session_id=?', (session_id,))
        expiry = await self.db.fetchone()
        if expiry is None:
            return True
        expiry = expiry[0]
        if time.time() > expiry:
            await self.db.execute('DELETE FROM scratchverifier_sessions \
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
        ).hexdigest().translate({48 + i: 65 + i for i in range(10)})
        await self.db.execute('INSERT INTO scratchverifier_usage (client_id, \
code, username, expiry) VALUES (?, ?, ?, ?)', (client_id, code, username,
                               int(time.time() + 1800)))
        return code

    async def get_code(self, client_id, username):
        await self.db.execute('SELECT code, expiry FROM scratchverifier_usage \
WHERE client_id=? AND username=?', (client_id, username))
        row = await self.db.fetchone()
        if row is None:
            return None
        if time.time() > row['expiry']:
            await self.end_verification(client_id, username)
            return None
        return row['code']

    async def end_verification(self, client_id, username):
        await self.db.execute('DELETE FROM scratchverifier_usage WHERE \
client_id=? AND username=?', (client_id, username))
