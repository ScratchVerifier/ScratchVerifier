import os
import re
import time
import json
from glob import glob
import traceback
import hmac
import asyncio
import mimetypes
from aiohttp import web, ClientSession, BasicAuth
from db import Database
from responses import *

class Server:
    def __init__(self, hook_secret, discord_hook, admins, name=None):
        """Initialize the Server.

        ``hook_secret``: str - Secret for GitHub webhook
        ``discord_hook``: str - Link for Discord error webhook
        ``admins``: set()-able - collection of admin usernames
        ``name``: str - name that appears in webhook messages
        """
        self.app = web.Application(middlewares=[self.errors])
        self.app.add_routes([
            web.put('/verify/{username}', self.verify),
            web.post('/verify/{username}', self.verified),
            web.delete('/verify/{username}', self.unverify),
            web.post('/users/{username}/login', self.login),
            web.post('/users/{username}/finish-login', self.finish_login),
            web.post('/users/{username}/logout', self.logout_user),
            web.get('/session', self.get_user),
            web.put('/session', self.put_user),
            web.patch('/session', self.reset_token),
            web.delete('/session', self.del_user),
            web.post('/session/logout', self.logout),
            web.get('/usage', self.logs),
            web.get('/usage/{logid}', self.log),
            web.get('/admin/ratelimits', self.get_ratelimits),
            web.get('/admin/ratelimits/{username}', self.get_ratelimit),
            web.patch('/admin/ratelimits', self.set_ratelimits),
            web.post('/admin/ratelimits/{username}', self.set_ratelimit),
            web.get('/admin/bans', self.get_bans),
            web.get('/admin/bans/{username}', self.get_ban),
            web.patch('/admin/bans', self.ban_multiple),
            web.post('/admin/bans/{username}', self.ban_single),
            web.delete('/admin/bans/{username}', self.unban),
            web.get('/admin/logs', self.admin_logs),
            web.get('/admin/logs/{logid}', self.admin_log),
            web.get('/admin/client/{clientid}', self.get_client),
            web.post('/webhook', self.gh_hook),
            web.get('/site/{path:.*}', self.file_handler),
            web.get('/site/', self.file_handler),
            web.get('/site', self.file_handler),
            web.get('/', self.redir_root),
            web.get('/docs/{path:.*}', self.docs_handler),
            web.get('/docs/', self.docs_handler),
            web.get('/docs', self.docs_handler),
            web.post('/debug/{dibool}', self.set_debug),
            web.view('/{path:.*}', self.not_found)
        ])
        self.session = ClientSession()
        self.ratelimits = {}
        self.db = Database(self.session)
        self.hook_secret = hook_secret.encode()
        self.discord_hook = discord_hook
        self.admins = set(admins)
        self.name = name
        self.debug = False
        self._debug = False
        self.debug_pass = False

    @web.middleware
    async def errors(self, request, handler):
        """Log to stdout and log errors to stdout and Discord webhook.

        ``request``: aiohttp.Request object
        ``handler``: method of this class

        Returns whatever the ``handler`` returns, or raises some exception.
        """
        print('%s %s %s' % (
            time.strftime('%Y-%m-%dT%H:%M:%SZ'),
            request.method,
            request.path_qs
        ))
        try:
            return await handler(request)
        except web.HTTPException as exc:
            raise
        except json.JSONDecodeError:
            raise web.HTTPBadRequest() from None
        except Exception as exc:
            print('Error in', handler.__name__, end='' if self._debug else '\n')
            if self._debug:
                print(':')
                print(traceback.format_exc())
            if self.discord_hook:
                await self.session.post(self.discord_hook, json={
                    'username': '{}ScratchVerifier Errors'.format(
                        (self.name + "'s ") if self.name else ''
                    ),
                    'embeds': [{
                        'color': 0xff0000,
                        'title': '500 Response Sent',
                        'fields': [
                            {'name': 'Request Path',
                             'value': f'`{request.method} {request.path_qs}`',
                             'inline': False},
                            {'name': 'Error traceback',
                             'value': '```{traceback.format_exc()}```',
                             'inline': False}
                        ]
                    }]
                })
            raise web.HTTPInternalServerError()

    # methods related to running the server

    async def run(self, port=DEFAULT_PORT, debug=False):
        """Coroutine to run the server.

        ``port``: int - port number to listen on
        ``debug``: bool - whether to allow /debug endpoints
        """
        self.runner = web.AppRunner(self.app)
        self._debug = debug
        await self.runner.setup()
        site = web.TCPSite(self.runner, '0.0.0.0', port)
        await site.start()

    async def stop(self):
        """Coroutine to close the server."""
        await self.runner.cleanup()
        await self.session.close()
        await self.db.close()

    async def _wakeup(self):
        """Background task to stop the server if any source files are modified.
        Doubles as a task that allows Ctrl+C to properly interrupt the loop
        on Windows systems.
        """
        files = glob(os.path.join(os.path.dirname(__file__), '*.py'))
        files.append(os.path.join(os.path.dirname(__file__),
                                  'sql', 'startup.sql'))
        files = {f: os.path.getmtime(f) for f in files}
        while 1:
            try:
                for i in files:
                    if os.path.getmtime(i) > files[i]:
                        return
                await asyncio.sleep(1)
            except:
                return

    def run_sync(self, port=DEFAULT_PORT, debug=False):
        """Synchronous method to run the server
        and close it upon KeyboardInterrupt.
        """
        loop = asyncio.get_event_loop()
        try:
            loop.run_until_complete(self.run(port, debug))
            loop.run_until_complete(self._wakeup())
        except KeyboardInterrupt:
            pass
        finally:
            loop.run_until_complete(self.stop())

    # methods related to checking values

    async def check_token(self, request):
        """Check if a request's token authentication is valid. Raise 401 if not.

        ``request``: aiohttp.Request object

        Returns int: client ID
        """
        if self.debug:
            return 0
        if 'Authorization' not in request.headers:
            raise web.HTTPUnauthorized()
        try:
            auth = BasicAuth.decode(request.headers['Authorization'])
            client_id = int(auth.login)
        except ValueError:
            raise web.HTTPUnauthorized() from None
        if not await self.db.client_matches(client_id, auth.password):
            raise web.HTTPUnauthorized()
        return client_id

    async def check_username(self, request):
        """Check if a username is a valid Scratch username. Raise 400 if not.

        ``request``: aiohttp.Request object

        Returns str: casefolded username
        """
        username = request.match_info.get('username', '')
        if not re.match(USERNAME_REGEX, username):
            raise web.HTTPBadRequest()
        return username.casefold()

    async def get_ratelimit_header(self, username, err_if_exceeded=True):
        """Get the ratelimit header for a ratelimited request.
        If ratelimits have been exceeded, raise 429 if ``err_if_exceeded``.

        ``username``: str - username of owner of client being ratelimited
        ``err_if_exceeded``: bool - whether to 429 if ratelimits are exceeded

        Returns str: Header value to send to client
        """
        row = await self.db.get_ratelimit(username)
        if row is None:
            await self.db.set_ratelimits(
                [{'username': username,
                  'ratelimit': DEFAULT_RATELIMIT}],
                None
            )
            row = {'ratelimit': DEFAULT_RATELIMIT}
        # left=(requests left)
        # resets=(timestamp when it resets to)
        # to=(this value)
        to = row['ratelimit']
        now = int(time.time())
        left, resets = self.ratelimits.setdefault(
            username, [to, now + LIMIT_PER_TIME])
        if resets <= now:
            self.ratelimits[username] = [to, now + LIMIT_PER_TIME]
            left, resets = self.ratelimits[username]
        if left == to:
            self.ratelimits[username][1] = now + LIMIT_PER_TIME
            resets = self.ratelimits[username][1]
        if err_if_exceeded:
            if self.ratelimits[username][0] <= 0:
                resp = web.HTTPTooManyRequests()
                resp.headers.add('Retry-After',
                                 str(self.ratelimits[username][1] - now))
                raise resp
            self.ratelimits[username][0] -= 1
            left = self.ratelimits[username][0]
        value = HEADER_FORMAT.format(left, resets, to)
        return value

    # the business part of the API

    async def verify(self, request):
        """PUT /verify/{username}"""
        client_id = await self.check_token(request)
        username = await self.check_username(request)
        code = await self.db.start_verification(client_id, username)
        response = web.json_response(Verification(
            code=code, username=username
        ).d())
        # get ratelimits but don't trigger them
        client_owner = (await self.db.get_client_info(client_id))['username']
        value = await self.get_ratelimit_header(client_owner, False)
        response.headers.add('X-Requests-Remaining', value)
        return response

    async def _verified(self, client_id, username):
        """Handle the logic of actually verifying the user.

        ``client_id``: int - client requesting verification
        ``username``: str - user to verify

        Returns bool: whether verification succeeded
        """
        if self.debug_pass:
            await self.db.end_verification(client_id, username, True)
            return True
        code = await self.db.get_code(client_id, username)
        if not code:
            raise web.HTTPNotFound()
        if self.debug:
            await self.db.end_verification(client_id, username, False)
            return False
        async with self.session.get(COMMENTS_API.format(
            username, int(time.time())
        )) as resp:
            if resp.status != 200:
                raise web.HTTPNotFound() #likely banned or nonexistent
            data = await resp.text()
        data = data.strip()
        if not data:
            await self.db.end_verification(client_id, username, False)
            return False #no comments at all, failed
        for m in re.finditer(COMMENTS_REGEX, data):
            if m.group(1).casefold() != username:
                continue
            if m.group(2).strip() == code:
                break
        else:
            await self.db.end_verification(client_id, username, False)
            return False #nothing was the code, failed
        await self.db.end_verification(client_id, username, True)
        return True

    async def verified(self, request):
        """POST /verify/{username}"""
        client_id = await self.check_token(request)
        username = await self.check_username(request)
        client_owner = (await self.db.get_client_info(client_id))['username']
        value = await self.get_ratelimit_header(client_owner)
        try:
            if await self._verified(client_id, username):
                raise web.HTTPNoContent()
            else:
                raise web.HTTPForbidden()
        except web.HTTPException as exc:
            exc.headers.add('X-Requests-Remaining', value)
            raise

    async def unverify(self, request):
        """DELETE /verify/{username}"""
        client_id = await self.check_token(request)
        username = await self.check_username(request)
        await self.db.end_verification(client_id, username, -1)
        client_owner = (await self.db.get_client_info(client_id))['username']
        value = await self.get_ratelimit_header(client_owner, False)
        response = web.HTTPNoContent()
        response.headers.add('X-Requests-Remaining', value)
        raise response

    # logging in to the website

    async def login(self, request):
        """POST /users/{username}/login"""
        username = await self.check_username(request)
        if (await self.db.get_ban(username)) is not None:
            raise web.HTTPForbidden()
        code = await self.db.start_verification(0, username)
        value = await self.get_ratelimit_header(username, False)
        response = web.json_response(Verification(
            code=code, username=username
        ).d())
        response.headers.add('X-Requests-Remaining', value)
        return response

    async def finish_login(self, request):
        """POST /users/{username}/finish-login"""
        username = await self.check_username(request)
        value = await self.get_ratelimit_header(username)
        if await self._verified(0, username):
            response = web.json_response(Admin(
                admin=username in self.admins
            ).d())
            response.set_cookie('session', await self.db.new_session(username),
                                max_age=SESSION_EXPIRY)
            response.headers.add('X-Requests-Remaining', value)
            return response
        else:
            response = web.HTTPUnauthorized()
            response.headers.add('X-Requests-Remaining', value)
            raise response

    async def logout_user(self, request):
        """POST /users/{username}/logout"""
        session_id = await self.check_session(request)
        data = User(**(await self.db.get_client(session_id)))
        username = await self.check_username(request)
        if username != data.username:
            raise web.HTTPForbidden()
        await self.db.logout_user(username)

    async def check_session(self, request):
        """Check whether a session ID is valid. Raise 401 if not.

        ``request``: aiohttp.Request object

        Returns int: session ID
        """
        if self.debug:
            return int(request.cookies['session'])
        session = request.cookies.get('session', '')
        if not (session or session.strip()):
            raise web.HTTPUnauthorized()
        try:
            session_id = int(session)
        except ValueError:
            raise web.HTTPUnauthorized() from None
        if await self.db.get_expired(session_id):
            raise web.HTTPUnauthorized()
        return session_id

    # manipulating API registration data

    async def get_user(self, request):
        """GET /session"""
        session_id = await self.check_session(request)
        data = await self.db.get_client(session_id)
        if data is None:
            raise web.HTTPNotFound()
        return web.json_response(data)

    async def put_user(self, request):
        """PUT /session"""
        session_id = await self.check_session(request)
        data = await self.db.get_client(session_id)
        if data is not None:
            raise web.HTTPConflict()
        if self.debug:
            session_id = 0 #prevent fake non-conflict debug IDs from registering
        data = await self.db.new_client(session_id)
        return web.json_response(data)

    async def reset_token(self, request):
        """PATCH /session"""
        session_id = await self.check_session(request)
        return web.json_response(await self.db.reset_token(session_id))

    async def del_user(self, request):
        """DELETE /session"""
        session_id = await self.check_session(request)
        await self.db.del_client(session_id)
        raise web.HTTPNoContent()

    async def logout(self, request):
        """POST /session/logout"""
        session_id = await self.check_session(request)
        await self.db.logout(session_id)
        raise web.HTTPNoContent()

    # usage logs

    async def logs(self, request, table='logs'):
        """GET /usage"""
        params = {}
        for k in {'limit', 'start', 'end', 'before',
                  'after', 'client_id', 'type'}:
            if k in request.query:
                try:
                    params[k] = int(request.query[k])
                except ValueError:
                    raise web.HTTPBadRequest() from None
        if 'start' in params and 'end' in params \
           and params['end'] < params['start']:
            raise web.HTTPBadRequest()
        if 'before' in params and 'after' in params \
           and params['after'] < params['before']:
            raise web.HTTPBadRequest()
        if 'username' in request.query:
            params['username'] = request.query['username']
        params.setdefault('limit', DEFAULT_LOG_LIMIT)
        if table == 'logs' and params['limit'] > MAX_LOG_LIMIT:
            raise web.HTTPForbidden()
        return web.json_response(await self.db.get_logs(table, **params))

    async def log(self, request, table='logs'):
        """GET /usage/{logid}"""
        log_id = request.match_info.get('logid', None)
        try:
            log_id = int(log_id)
        except ValueError:
            raise web.HTTPNotFound() from None
        data = await self.db.get_log(log_id, table=table)
        if data is None:
            raise web.HTTPNotFound()
        return web.json_response(data)

    # admin panel

    async def admin_session(self, request):
        """Check if a session owner is an admin. Raise 401 if not.

        ``request``: aiohttp.Request object

        Returns (int, str): session ID and username
        """
        session_id = await self.check_session(request)
        username = await self.db.username_from_session(session_id)
        if username not in self.admins:
            raise web.HTTPUnauthorized()
        return username

    # ratelimit endpoints

    def get_client_id(self, request, badifinvalid=False):
        """Get the client ID from the request.
        Raise 404 if non-integer client ID is passed (or not passed)
        or 400 if ``badifinvalid`` is True

        ``request``: aiohttp.Request object
        ``badifinvalid``: bool - if True, invalid ID raises 400, not 404

        Returns int: client ID
        """
        client_id = request.match_info.get('clientid', None)
        try:
            client_id = int(client_id)
        except ValueError:
            if badifnot:
                raise web.HTTPBadRequest() from None
            raise web.HTTPNotFound() from None
        return client_id

    async def get_ratelimits(self, request):
        """GET /admin/ratelimits"""
        await self.admin_session(request)
        return web.json_response(await self.db.get_ratelimits())

    async def get_ratelimit(self, request):
        """GET /admin/ratelimits/{username}"""
        await self.admin_session(request)
        username = await self.check_username(request)
        row = await self.db.get_ratelimit(username) # entire row
        if row is None:
            raise web.HTTPNotFound()
        return web.json_response(PartialRatelimit(
            ratelimit=row['ratelimit']
        ).d())

    async def set_ratelimits(self, request):
        """PATCH /admin/ratelimits"""
        performer = await self.admin_session(request)
        data = await request.json()
        if not isinstance(data, list):
            raise web.HTTPBadRequest()
        data = [i for i in data
                if isinstance(i.get('username', None), str)
                and USERNAME_REGEX.match(i['username'])
                and isinstance(i.get('ratelimit', None), int)
                and i['ratelimit'] > 0]
        for i in data:
            if i['username'] in self.ratelimits:
                # reset ratelimit tracking once limits change
                del self.ratelimits[data['username']]
        await self.db.set_ratelimits(data, performer)
        raise web.HTTPNoContent()

    async def set_ratelimit(self, request):
        """POST /admin/ratelimits/{username}"""
        performer = await self.admin_session(request)
        username = await self.check_username(request)
        data = await request.json()
        if not isinstance(data.get('ratelimit', None), int) \
           or data['ratelimit'] <= 0:
            raise web.HTTPBadRequest()
        if username in self.ratelimits:
            # reset ratelimit tracking once limits change
            del self.ratelimits[username]
        await self.db.set_ratelimits(
            [{'username': username,
              'ratelimit': data['ratelimit']}],
            performer
        )
        raise web.HTTPNoContent()

    # banned user endpoints

    async def get_bans(self, request):
        """GET /admin/bans"""
        await self.admin_session(request)
        return web.json_response(await self.db.get_bans())

    async def get_ban(self, request):
        """GET /admin/bans/{username}"""
        await self.admin_session(request)
        username = await self.check_username(request)
        row = await self.db.get_ban(username) # entire row
        if row is None:
            raise web.HTTPNotFound()
        return web.json_response(PartialBan(
            expiry=row['expiry']
        ).d())

    async def ban_multiple(self, request):
        """PATCH /admin/bans"""
        performer = await self.admin_session(request)
        data = [i for i in await request.json()
                if isinstance(i['username'], str)
                and USERNAME_REGEX.match(i['username'])
                and isinstance(i.get('expiry', ...), (int, type(None)))
                and (i['expiry'] is None
                     or i['expiry'] > time.time())]
        await self.db.set_bans(data, performer)
        raise web.HTTPNoContent()

    async def ban_single(self, request):
        """POST /admin/bans/{username}"""
        performer = await self.admin_session(request)
        username = await self.check_username(request)
        data = await request.json()
        if not isinstance(data.get('expiry', ...), (int, type(None))) \
           or isinstance(data['expiry'], int) and data['expiry'] <= time.time():
            raise web.HTTPBadRequest()
        await self.db.set_bans(
            [{'username': username,
              'expiry': data['expiry']}],
            performer
        )
        raise web.HTTPNoContent()

    async def unban(self, request):
        """DELETE /admin/bans/{username}"""
        performer = await self.admin_session(request)
        username = await self.check_username(request)
        await self.db.del_ban(username, performer)
        raise web.HTTPNoContent()

    # admin audit logs

    async def admin_logs(self, request):
        """GET /admin/logs"""
        await self.admin_session(request)
        return await self.logs(request, 'auditlogs')

    async def admin_log(self, request):
        """GET /admin/logs/{logid}"""
        await self.admin_session(request)
        return await self.log(request, 'auditlogs')

    # miscellaneous endpoints, some undocumented

    async def get_client(self, request):
        """GET /admin/client/{clientid}"""
        await self.admin_session(request)
        client_id = self.get_client_id(request)
        client = await self.db.get_client_info(client_id)
        if client is None:
            raise web.HTTPNotFound()
        username = client['username']
        client['token'] = client['token'][:TOKEN_CENSOR_LEN] \
                          + '*' * (len(client['token']) - TOKEN_CENSOR_LEN)
        row = await self.db.get_ratelimit(username)
        client['ratelimit'] = row and row['ratelimit']
        return web.json_response(client)

    async def gh_hook(self, request):
        """POST /webhook"""
        if 'X-Hub-Signature' not in request.headers:
            raise web.HTTPForbidden()
        algo, hash = request.headers['X-Hub-Signature'].split('=')
        digest = hmac.new(self.hook_secret, await request.read(), algo)
        digest = digest.hexdigest()
        if not hmac.compare_digest(digest, hash):
            raise web.HTTPForbidden()
        data = await request.json()
        if data['ref'] != 'refs/heads/master':
            raise web.HTTPNoContent() #success, but no action
        os.system('cd {} && git pull --rebase origin'.format(
            os.path.dirname(__file__)
        ))
        raise web.HTTPNoContent()

    async def set_debug(self, request):
        """POST /debug/{dibool}"""
        if not self._debug:
            raise web.HTTPNotFound()
        val = int(request.match_info['dibool'])
        # if True, client_id-token auth is not required
        self.debug = bool(val & 1)
        # if True, verifications are treated as successful
        # (i.e. pretend the comment was posted)
        self.debug_pass = bool(val & 2)
        raise web.HTTPNoContent()

    async def _file_handler(self, request, WEB_ROOT):
        WEB_ROOT = os.path.join(os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))
        ), WEB_ROOT)
        PATH = request.match_info.get('path', 'index.html') or 'index.html'
        if '.' not in PATH.split('/')[-1]:
            PATH += '/index.html'
        FILE = os.path.join(WEB_ROOT, PATH)
        if request.if_modified_since:
            if os.path.getmtime(FILE) <= \
                    request.if_modified_since.timestamp():
                raise web.HTTPNotModified()
        if request.if_unmodified_since:
            if os.path.getmtime(FILE) > \
                    request.if_unmodified_since.timestamp():
                raise web.HTTPPreconditionFailed()
        try:
            with open(FILE, 'rb') as f:
                range = request.http_range
                if range.stop:
                    if range.start:
                        f.seek(range.start)
                        rsize = range.stop - range.start
                    else:
                        rsize = range.stop
                elif range.start:
                    f.seek(range.start)
                    rsize = -1
                else:
                    rsize = -1
                data = f.read(rsize)
            ct = mimetypes.guess_type(PATH)
            return web.Response(body=data, content_type=ct[0], charset=ct[1])
        except FileNotFoundError:
            raise web.HTTPNotFound()

    async def file_handler(self, request):
        """GET /site, /site/, /site/{path}"""
        return await self._file_handler(request, 'public')

    async def docs_handler(self, request):
        """GET /docs, /docs/, /docs/{path}"""
        return await self._file_handler(request, 'docs')

    async def redir_root(self, request):
        """GET /"""
        raise web.HTTPMovedPermanently('/site')

    async def not_found(self, request):
        raise web.HTTPNotFound()
