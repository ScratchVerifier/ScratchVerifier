import os
import re
import time
from glob import glob
import traceback
import hmac
import asyncio
import mimetypes
from aiohttp import web, ClientSession, BasicAuth
from db import Database, USERS_API
from responses import *

DEFAULT_PORT = 8888
COMMENTS_API = 'https://scratch.mit.edu/site-api/comments/user/{}/\
?page=1&salt={}'
USERNAME_REGEX = re.compile('[A-Za-z0-9_-]{3,20}')
COMMENTS_REGEX = re.compile(r"""<div id="comments-\d+" class="comment +" data-comment-id="\d+">.*?<div class="actions-wrap">.*?<div class="name">\s+<a href="/users/([_a-zA-Z0-9-]+)">\1</a>\s+</div>\s+<div class="content">(.*?)</div>""", re.S)

class Server:
    def __init__(self, hook_secret, discord_hook, name=None):
        self.app = web.Application(middlewares=[self.errors])
        self.app.add_routes([
            web.put('/verify/{username}', self.verify),
            web.post('/verify/{username}', self.verified),
            web.delete('/verify/{username}', self.unverify),
            web.post('/users/{username}/login', self.login),
            web.post('/users/{username}/finish-login', self.finish_login),
            web.post('/users/{username}/logout', self.logout_user),
            web.get('/session/{session}', self.get_user),
            web.put('/session/{session}', self.put_user),
            web.patch('/session/{session}', self.reset_token),
            web.delete('/session/{session}', self.del_user),
            web.post('/session/{session}/logout', self.logout),
            web.get('/usage', self.logs),
            web.get('/usage/{logid}', self.log),
            web.post('/webhook', self.gh_hook),
            web.get('/site/{path:.*}', self.file_handler),
            web.get('/site/', self.file_handler),
            web.get('/site', self.file_handler),
            web.get('/docs/{path:.*}', self.docs_handler),
            web.get('/docs/', self.docs_handler),
            web.get('/docs', self.docs_handler),
            web.view('/{path:.*}', self.not_found)
        ])
        self.session = ClientSession()
        self.db = Database(self.session)
        self.hook_secret = hook_secret
        self.discord_hook = discord_hook
        self.name = name

    @web.middleware
    async def errors(self, request, handler):
        print('%s %s %s' % (
            time.strftime('%Y-%m-%dT%H:%M:%SZ'),
            request.method,
            request.path_qs
        ))
        try:
            return await handler(request)
        except web.HTTPException as exc:
            raise
        except Exception as exc:
            await self.session.post(self.discord_hook, json={
                'username': '{}ScratchVerifier Errors'.format(
                    (self.name + "'s ") if self.name else ''
                ),
                'embeds': [{
                    'color': 0xff0000,
                    'title': '500 Response Sent',
                    'fields': [
                        {'name': 'Request Path',
                         'value': '`%s %s`' % (request.method, request.path_qs),
                         'inline': False},
                        {'name': 'Error traceback',
                         'value': '```%s```' % traceback.format_exc(),
                         'inline': False}
                    ]
                }]
            })
            raise

    async def run(self, port=DEFAULT_PORT):
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, '0.0.0.0', port)
        await site.start()

    async def stop(self):
        await self.runner.cleanup()
        await self.session.close()
        await self.db.close()

    async def _wakeup(self):
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

    def run_sync(self, port=DEFAULT_PORT):
        loop = asyncio.get_event_loop()
        try:
            loop.run_until_complete(self.run(port))
            loop.run_until_complete(self._wakeup())
        except KeyboardInterrupt:
            pass
        finally:
            loop.run_until_complete(self.stop())

    async def check_token(self, request):
        if 'Authorization' not in request.headers:
            raise web.HTTPUnauthorized()
        auth = BasicAuth.decode(request.headers['Authorization'])
        client_id = int(auth.login)
        if not await self.db.client_matches(client_id, auth.password):
            raise web.HTTPUnauthorized()
        return client_id

    async def check_username(self, request):
        username = request.match_info.get('username', None)
        if not re.match(USERNAME_REGEX, username):
            raise web.HTTPBadRequest()
        async with self.session.get(USERS_API.format(username)) as resp:
            if resp.status != 200:
                raise web.HTTPNotFound()
        return username.casefold()

    async def verify(self, request):
        client_id = await self.check_token(request)
        username = await self.check_username(request)
        code = await self.db.start_verification(client_id, username)
        return web.json_response(Verification(
            code=code, username=username
        ).d())

    async def _verified(self, client_id, username):
        code = await self.db.get_code(client_id, username)
        if not code:
            raise web.HTTPNotFound()
        async with self.session.get(COMMENTS_API.format(
            username, int(time.time())
        )) as resp:
            if resp.status != 200:
                raise web.HTTPNotFound() #likely banned or something
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
        client_id = await self.check_token(request)
        username = await self.check_username(request)
        if await self._verified(client_id, username):
            raise web.HTTPNoContent()
        else:
            raise web.HTTPForbidden()

    async def unverify(self, request):
        client_id = await self.check_token(request)
        username = await self.check_username(request)
        await self.db.end_verification(client_id, username, -1)
        raise web.HTTPNoContent()

    async def login(self, request):
        username = await self.check_username(request)
        code = await self.db.start_verification(0, username)
        return web.json_response(Verification(
            code=code, username=username
        ).d())

    async def finish_login(self, request):
        username = await self.check_username(request)
        if await self._verified(0, username):
            return web.json_response(Session(
                session=await self.db.new_session(username)
            ).d())
        else:
            raise web.HTTPUnauthorized()

    async def logout_user(self, request):
        session_id = await self.check_session(request)
        data = User(**(await self.db.get_client(session_id)))
        username = await self.check_username(request)
        if username != data.username:
            raise web.HTTPForbidden()
        await self.db.logout_user(username)

    async def check_session(self, request):
        session = request.match_info.get('session',
                                         request.query.get('session', ''))
        if not (session or session.strip()):
            raise web.HTTPUnauthorized()
        try:
            session_id = int(session)
        except ValueError:
            raise web.HTTPUnauthorized() from None
        if await self.db.get_expired(session_id):
            raise web.HTTPUnauthorized()
        return session_id

    async def get_user(self, request):
        session_id = await self.check_session(request)
        data = await self.db.get_client(session_id)
        if data is None:
            raise web.HTTPNotFound()
        return web.json_response(data)

    async def put_user(self, request):
        session_id = await self.check_session(request)
        data = await self.db.get_client(session_id)
        if data is not None:
            raise web.HTTPConflict()
        data = await self.db.new_client(session_id)
        return web.json_response(data)

    async def reset_token(self, request):
        session_id = await self.check_session(request)
        await self.db.reset_token(session_id)
        return await self.get_user(request)

    async def del_user(self, request):
        session_id = await self.check_session(request)
        await self.db.del_client(session_id)
        raise web.HTTPNoContent()

    async def logout(self, request):
        session_id = await self.check_session(request)
        await self.db.logout(session_id)
        raise web.HTTPNoContent()

    async def logs(self, request):
        params = {}
        for k in {'limit', 'start', 'end', 'before',
                  'after', 'client_id', 'type'}:
            if k in request.query:
                try:
                    params[k] = int(request.query[k])
                except ValueError:
                    raise web.HTTPBadRequest() from None
        if 'username' in request.query:
            params['username'] = request.query['username']
        if params.get('limit', 100) > 500:
            raise web.HTTPForbidden()
        return web.json_response(await self.db.get_logs(**params))

    async def log(self, request):
        log_id = request.match_info.get('logid', None)
        try:
            log_id = int(log_id)
        except ValueError:
            raise web.HTTPNotFound() from None
        data = await self.db.get_log(log_id)
        if data is None:
            raise web.HTTPNotFound()
        return web.json_response(data)

    async def gh_hook(self, request):
        if 'X-Hub-Signature' not in request.headers:
            raise web.HTTPUnauthorized()
        digest = hmac.new(self.hook_secret, await request.read(), 'sha1')
        digest = digest.hexdigest()
        if not hmac.compare_digest(digest, request.headers['X-Hub-Signature']):
            raise web.HTTPUnauthorized()
        data = await request.json()
        if data['ref'] != 'refs/heads/master':
            raise web.HTTPNoContent() #success, but no action
        os.system('cd {} && git pull --rebase origin'.format(
            os.path.dirname(__file__)
        ))
        raise web.HTTPNoContent()

    async def _file_handler(self, request, WEB_ROOT):
        WEB_ROOT = os.path.join(os.path.dirname(
            os.path.dirname(__file__)
        ), WEB_ROOT)
        PATH = request.match_info.get('path', 'index.html') or 'index.html'
        if '.' not in PATH.split('/')[-1]:
            PATH += '/index.html'
        FILE = os.path.join(WEB_ROOT, PATH)
        if request.if_modified_since:
            if os.path.getmtime(FILE) <= \
                    request.if_modified_since.total_seconds():
                raise web.HTTPNotModified()
        if request.if_unmodified_since:
            if os.path.getmtime(FILE) > \
                    request.if_unmodified_since.total_seconds():
                raise web.HTTPPreconditionFailed()
        try:
            with open(FILE, 'rb') as f:
                range = request.http_range
                f.seek(range.start or 0)
                data = f.read(((range.stop or 0) - (range.start or 0)) or -1)
            ct = mimetypes.guess_type(PATH)
            return web.Response(body=data, content_type=ct[0], charset=ct[1])
        except FileNotFoundError:
            raise web.HTTPNotFound()

    async def file_handler(self, request):
        return await self._file_handler(request, 'public')

    async def docs_handler(self, request):
        return await self._file_handler(request, 'docs')

    async def not_found(self, request):
        raise web.HTTPNotFound()
