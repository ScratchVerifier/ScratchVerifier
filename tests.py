"""Test actual API endpoints"""
import sys
import time
import os
import unittest
from http.cookiejar import http2time # undocumented
import requests
sys.path.append(os.path.dirname(__file__))
from backend.responses import *

API_ROOT = 'http://localhost:8888'
session = requests.session()

def set_session(session_id):
    """Set session=session_id in cookies"""
    # simply overwriting isn't enough, must unset before set
    del session.cookies['session']
    session.cookies['session'] = str(session_id)

class TestApi(unittest.TestCase):
    """Test actual API endpoints."""
    def test_start(self):
        """Test PUT /verify/{}"""
        # skip client_id-token auth
        session.post(API_ROOT + '/debug/1')
        # start verification
        resp = session.put(API_ROOT + '/verify/kenny2scratch')
        self.assertEqual(resp.status_code, 200, 'not HTTP 200 on success')
        resp = resp.json()

        # response must implement structure
        self.assertIsInstance(resp, Verification, 'not Verification')
        # usernames are casefolded
        self.assertEqual(resp['username'], 'kenny2scratch', 'not casefolded')

        # without finishing verification, the code should be cached
        code = resp['code']
        resp = session.put(API_ROOT + '/verify/kenny2scratch').json()
        self.assertNotEqual(resp['code'], code, 'same PUT and same code')

        # regex-invalid names 400
        resp = session.put(API_ROOT + '/verify/Impossible Username')
        self.assertEqual(resp.status_code, 400, 'not HTTP 400 on invalid name')

        # disable all auth bypass
        session.post(API_ROOT + '/debug/0')
        # try verifying now
        resp = session.put(API_ROOT + '/verify/kenny2scratch')
        self.assertEqual(resp.status_code, 401, 'not HTTP 401 on missing auth')

    def test_end(self):
        """Test POST /verify/{}"""
        # skip client_id-token auth
        # pretend verification code was posted
        session.post(API_ROOT + '/debug/3')
        session.put(API_ROOT + '/verify/kenny2scratch')
        # moment of truth: finish verification
        resp = session.post(API_ROOT + '/verify/kenny2scratch')
        self.assertEqual(resp.status_code, 204, 'not HTTP 204 on success')

        # continue skipping auth, but don't pretend verification
        session.post(API_ROOT + '/debug/1')
        session.put(API_ROOT + '/verify/kenny2scratch')
        # moment of truth: fail verification
        resp = session.post(API_ROOT + '/verify/kenny2scratch')
        self.assertEqual(resp.status_code, 403, 'not HTTP 403 on failure')

        # with no start, there is no end
        resp = session.post(API_ROOT + '/verify/kenny2scratch')
        self.assertEqual(resp.status_code, 404, 'not HTTP 404 without start')

    def test_cancel(self):
        """Test DELETE /verify/{}"""
        # skip client_id-token auth
        session.post(API_ROOT + '/debug/1')
        # start verification...
        session.put(API_ROOT + '/verify/kenny2scratch')
        # ...then CANCEL it
        resp = session.delete(API_ROOT + '/verify/kenny2scratch')
        self.assertEqual(resp.status_code, 204, 'not HTTP 204 on success')

class TestLogin(unittest.TestCase):
    """Test the login and registration flow."""
    def test_login(self):
        """Test POST /users/{}/login"""
        # turn off all backdoors just in case
        session.post(API_ROOT + '/debug/0')
        resp = session.post(API_ROOT + '/users/kenny2scratch/login')
        self.assertEqual(resp.status_code, 200, 'login start unsuccessful')
        resp = resp.json()
        # response must implement structure
        self.assertIsInstance(resp, Verification, 'not Verification')

        # regex-invalid names 400
        resp = session.post(API_ROOT + '/users/Impossible Username/login')
        self.assertEqual(resp.status_code, 400, 'not HTTP 400 on invalid name')

    def test_finish_login(self):
        """Test POST /users/{}/finish-login"""
        # pretend comment was posted
        session.post(API_ROOT + '/debug/2')
        session.post(API_ROOT + '/users/kenny2scratch/login')
        resp = session.post(API_ROOT + '/users/kenny2scratch/finish-login')
        # successful login if comment was posted
        self.assertEqual(resp.status_code, 200, 'login not successful')

        resp = resp.json()
        # response must implement structure
        self.assertIsInstance(resp, Admin, 'response was not Admin object')
        # I'm an admin :)
        self.assertTrue(resp['admin'], 'kenny2scratch should be an admin')

        # try that test again with non-admin
        session.post(API_ROOT + '/users/deathly_hallows/login')
        resp = session.post(API_ROOT + '/users/deathly_hallows/finish-login')
        resp = resp.json()
        self.assertFalse(resp['admin'], 'deathly_hallows should not be admin')

        # stop pretending, this is the real world
        session.post(API_ROOT + '/debug/0')
        session.post(API_ROOT + '/users/kenny2scratch/login')
        resp = session.post(API_ROOT + '/users/kenny2scratch/finish-login')
        # failed login 401s
        self.assertEqual(resp.status_code, 401, 'not HTTP 401 on failure')

        resp = session.post(API_ROOT + '/users/kenny2scratch/finish-login')
        # unstarted login 404s
        self.assertEqual(resp.status_code, 404, 'not HTTP 404 without start')

    def test_get_client(self):
        """Test GET /session"""
        # bypass real session checking
        session.post(API_ROOT + '/debug/1')
        # session=0 is a signal to the DB as well as the API
        set_session(0)
        resp = session.get(API_ROOT + '/session')
        # successful get should be successful status
        self.assertEqual(resp.status_code, 200, 'not 200')

        resp = resp.json()
        # response must implement structure
        self.assertIsInstance(resp, User, 'response was not User object')

        # session=-1 is guaranteed to be an invalid session ID,
        # but we're still bypassing session checking...
        set_session(-1)
        resp = session.get(API_ROOT + '/session')
        # ...so it's a valid session with no associated client
        self.assertEqual(resp.status_code, 404, 'not 404 for no client')

        # turn on session checking
        session.post(API_ROOT + '/debug/0')
        resp = session.get(API_ROOT + '/session') # session cookie is still -1
        # now it realizes there's no session with that ID in the first place
        self.assertEqual(resp.status_code, 401, 'not 401 on missing auth')

    def test_put_client(self):
        """Test PUT /session"""
        # skip real session checking
        session.post(API_ROOT + '/debug/1')
        # non-backdoor session ID, but checking is backdoored
        set_session(1)
        resp = session.put(API_ROOT + '/session')
        self.assertEqual(resp.status_code, 200, 'real session ID still failed')

        resp = resp.json()
        # response must implement structure
        self.assertIsInstance(resp, User, 'not User')

        # the backdoor session already has a dummy client registered,
        set_session(0)
        resp = session.put(API_ROOT + '/session')
        # so it should conflict when trying to register a new one
        self.assertEqual(resp.status_code, 409, 'not 409 on existing client')

        # turn real session checking back on
        session.post(API_ROOT + '/debug/0')
        set_session(1)
        resp = session.put(API_ROOT + '/session')
        self.assertEqual(resp.status_code, 401, 'not 401 on missing auth')

    def test_patch_client(self):
        """Test PATCH /session"""
        # bypass real session checking
        session.post(API_ROOT + '/debug/1')
        set_session(0)
        # get previous token for later use
        old_token = session.get(API_ROOT + '/session').json()['token']

        resp = session.patch(API_ROOT + '/session')
        # with a valid session, the response should be successful
        self.assertEqual(resp.status_code, 200, 'PATCH was unsuccessful')

        resp = resp.json()
        # response must implement structure
        self.assertIsInstance(resp, User, 'not User')
        # the token should have been reset
        self.assertNotEqual(resp['token'], old_token, 'token was not reset')

        # ensure real session checking still works
        session.post(API_ROOT + '/debug/0')
        set_session(1)
        resp = session.patch(API_ROOT + '/session')
        self.assertEqual(resp.status_code, 401, 'not 401 on missing auth')

    def test_delete_client(self):
        """Test DELETE /session"""
        # bypass real session checking
        session.post(API_ROOT + '/debug/1')
        set_session(0)

        resp = session.delete(API_ROOT + '/session')
        # blank response
        self.assertEqual(resp.status_code, 204, 'successful DELETE should 204')

        # check real session checking
        session.post(API_ROOT + '/debug/0')
        set_session(1)
        resp = session.delete(API_ROOT + '/session')
        self.assertEqual(resp.status_code, 401, 'not 401 on missing auth')

class TestLogging(unittest.TestCase):
    """Test logging-related endpoints."""
    @classmethod
    def setUpClass(cls):
        """Do some stuff so that the logs are populated"""
        # bypass auth and pretend verification works
        session.post(API_ROOT + '/debug/3')
        # add a start and successful verification
        session.put(API_ROOT + '/verify/kenny2scratch')
        session.post(API_ROOT + '/verify/kenny2scratch')

        # no need to pretend verification works when it's being cancelled
        session.post(API_ROOT + '/debug/1')
        # add a start and cancelled verification
        session.put(API_ROOT + '/verify/kenny2scratch')
        session.delete(API_ROOT + '/verify/kenny2scratch')

        # turn off debug because it's not necessary for the rest
        session.post(API_ROOT + '/debug/0')

    def test_logs(self):
        """Test GET /usage"""
        resp = session.get(API_ROOT + '/usage')
        # a well-formed request should always be a 200
        self.assertEqual(resp.status_code, 200, 'not 200')
        resp = resp.json()
        self.assertIsInstance(resp, list, 'not a *list* of Logs')
        # response items must implement structure
        self.assertIsInstance(resp[0], Log, 'not a list of *Log*s')

        # match entries with previous actions
        self.assertEqual(resp[0]['log_type'], 4, 'last log was not invalidated')
        self.assertEqual(resp[0]['username'], 'kenny2scratch', 'wrong name')
        self.assertEqual(resp[1]['log_type'], 1, '2nd-last log was not started')
        self.assertEqual(resp[2]['log_type'], 2, '3rd-last log was not OK')

    def test_important_log_params(self):
        """Test GET /usage parameters"""
        # ensure quota exceeding fails
        resp = session.get(API_ROOT + '/usage', params={'limit': 600})
        self.assertEqual(resp.status_code, 403, 'not 403 on big limit')

        # try limits
        resp = session.get(API_ROOT + '/usage', params={'limit': 2}).json()
        self.assertEqual(len(resp), 2, 'requested 2 entries but got sth else')

        # try pagination
        last_id = resp[-1]['log_id']
        resp = session.get(API_ROOT + '/usage',
                           params={'start': last_id}).json()
        # next page should be before (in time) the last
        self.assertGreater(last_id, resp[0]['log_id'],
                           'first log before last is after it??')

    def test_log(self):
        """Test GET /usage/{}"""
        resp = session.get(API_ROOT + '/usage/-1')
        # no negative log IDs
        self.assertEqual(resp.status_code, 404, 'not 404 on nonexistent log')

        # get specific log to fetch
        resp = session.get(API_ROOT + '/usage').json()
        log = resp[-1]

        resp = session.get('%s/usage/%s' % (API_ROOT, log['log_id']))
        # existent log should be success
        self.assertEqual(resp.status_code, 200, 'existent log not 200')

        resp = resp.json()
        # response must implement structure
        self.assertIsInstance(resp, Log, 'response was not Log object')
        # check this is actually the same log
        self.assertEqual(resp, log, 'not the same log')

class TestRatelimits(unittest.TestCase):
    """Test ratelimits (API endpoints only)."""
    @classmethod
    def setUpClass(cls):
        """All of these tests requires an admin session."""
        set_session(0)
        session.post(API_ROOT + '/debug/1')
        session.post(API_ROOT + '/admin/ratelimits/nochanges',
                     json={'ratelimit': 60})

    def test_get_all(self):
        """Test GET /admin/ratelimits"""
        # using admin session: on
        session.post(API_ROOT + '/debug/1')

        resp = session.get(API_ROOT + '/admin/ratelimits')
        # unless unauthenticated, response should be 200
        self.assertEqual(resp.status_code, 200, 'ratelimits returned non-200')

        resp = resp.json()
        # response must implement structures
        self.assertIsInstance(resp, list, 'response not *list* of Ratelimits')
        self.assertIsInstance(resp[0], Ratelimit, 'response not Ratelimits')

        found = False
        for ratelimit in resp:
            if ratelimit['username'] == 'nochanges':
                # setup set limit to 60, make sure that persists
                self.assertEqual(ratelimit['ratelimit'], 60,
                                 'limit is different from what was set')
                found = True
                break
        # setup set limit for me, make sure it's there
        self.assertTrue(found, 'no ratelimit for nochanges')

        # using admin session: off
        session.post(API_ROOT + '/debug/0')

        resp = session.get(API_ROOT + '/admin/ratelimits')
        # unauthenticated must be 401, otherwise it's a security issue
        self.assertEqual(resp.status_code, 401, 'unauthenticated MUST be 401')

    def test_get_one(self):
        """Test GET /admin/ratelimits/{}"""
        # using admin session: on
        session.post(API_ROOT + '/debug/1')

        resp = session.get(API_ROOT + '/admin/ratelimits/nochanges')
        # this was set earlier, so it should be 200
        self.assertEqual(resp.status_code, 200, 'ratelimit returned non-200')

        resp = resp.json()
        # response must implement structure
        self.assertIsInstance(resp, PartialRatelimit, 'response not PR')

        # setup set limit to 60, make sure that persists
        self.assertEqual(resp['ratelimit'], 60,
                         'limit is different from what was set')

        resp = session.get(API_ROOT + '/admin/ratelimits/validbutnonexistent')
        # not set, not found
        self.assertEqual(resp.status_code, 404, 'not 404 for valid username')

        resp = session.get(API_ROOT + '/admin/ratelimits/Impossible Username')
        # not valid, bad request
        self.assertEqual(resp.status_code, 400, 'not 400 for invalid username')

        # using admin session: off
        session.post(API_ROOT + '/debug/0')

        resp = session.get(API_ROOT + '/admin/ratelimits/nochanges')
        # unauthenticated, unauthorized
        self.assertEqual(resp.status_code, 401, 'unauthenticated MUST be 401')

    def test_set_all(self):
        """Test PATCH /admin/ratelimits"""
        # using admin session: on
        session.post(API_ROOT + '/debug/1')

        resp = session.patch(API_ROOT + '/admin/ratelimits', json=[
            {'username': 'validusername', 'ratelimit': 50},
            {'username': 'anothervalid', 'ratelimit': 20},
        ])
        # success is a blank response
        self.assertEqual(resp.status_code, 204, 'unsuccessful PATCH')

        # make sure only those were set
        resp = session.get(API_ROOT + '/admin/ratelimits/nochanges').json()
        self.assertEqual(resp['ratelimit'], 60, 'PATCH modified nochanges')

        # make sure those that were set were set right
        resp = session.get(API_ROOT + '/admin/ratelimits/validusername')
        self.assertEqual(resp.status_code, 200, 'PATCH never set validusername')
        resp = resp.json()
        self.assertEqual(resp['ratelimit'], 50, 'incorrect ratelimit')

        # make sure invalid format errors too
        resp = session.patch(API_ROOT + '/admin/ratelimits',
                             data={'youfellforit': 'fool!'})
        self.assertEqual(resp.status_code, 400, 'non-JSON never errored')

        # using admin session: off
        session.post(API_ROOT + '/debug/0')

        resp = session.patch(API_ROOT + '/admin/ratelimits', json=[
            {'username': 'validusername', 'ratelimit': 20},
            {'username': 'anothervalid', 'ratelimit': 50},
        ])
        # now more than ever, unauthenticated must be unauthorized
        self.assertEqual(resp.status_code, 401, 'unauthenticated MUST be 401')

    def test_set_one(self):
        """Test POST /admin/ratelimits/{}"""
        # using admin session: on
        session.post(API_ROOT + '/debug/1')

        resp = session.post(API_ROOT + '/admin/ratelimits/yetanother',
                            json={'ratelimit': 20})
        # success is blank
        self.assertEqual(resp.status_code, 204, 'unsuccessful POST')

        # make sure it was set
        resp = session.get(API_ROOT + '/admin/ratelimits/yetanother')
        self.assertEqual(resp.status_code, 200, 'POST never set yetanother')
        resp = resp.json()
        self.assertEqual(resp['ratelimit'], 20, 'incorrect ratelimit')

        # make sure invalid data errors
        resp = session.post(API_ROOT + '/admin/ratelimits/yetanother',
                            data={'thundercross': 'splitattack!'})
        self.assertEqual(resp.status_code, 400, 'non-JSON never errored')
        resp = session.post(API_ROOT + '/admin/ratelimits/yetanother',
                            json={'ratelimit': -2})
        self.assertEqual(resp.status_code, 400, '-ve limit never errored')
        resp = session.post(API_ROOT + '/admin/ratelimits/yetanother',
                            json={'ratelimit': 'max'})
        self.assertEqual(resp.status_code, 400, 'non-int limit never errored')

        # using admin session: off
        session.post(API_ROOT + '/debug/0')

        resp = session.post(API_ROOT + '/admin/ratelimits/yetanother',
                            json={'ratelimit': 50})
        # you know the drill
        self.assertEqual(resp.status_code, 401, 'unauthenticated, MUST be 401')

    def test_ratelimiting(self):
        """Test actually being ratelimited."""
        # bypass auth and make all verifications successful
        session.post(API_ROOT + '/debug/3')
        set_session(0)
        # set up a ratelimit that is easily testable
        session.post(API_ROOT + '/admin/ratelimits/kenny2scratch',
                     json={'ratelimit': 2})

        resp = session.put(API_ROOT + '/verify/deathly_hallows')
        now = int(http2time(resp.headers['Date']))
        # anything that calls the verify API returns a X-Requests-Remaining
        # header like left=2, resets=1598514504, to=2
        self.assertIn('X-Requests-Remaining', resp.headers, 'no custom header')
        # *starting* verification should not trigger ratelimits
        self.assertEqual(resp.headers['X-Requests-Remaining'],
                         HEADER_FORMAT.format(2, now + LIMIT_PER_TIME, 2),
                         'incorrect header format or values')

        time.sleep(2)
        # the reset time should always be LIMIT_PER_TIME seconds into the future
        # up until "left" is less than "to"
        resp = session.post(API_ROOT + '/verify/deathly_hallows')
        now = int(http2time(resp.headers['Date']))
        # the POST API should return it too
        self.assertIn('X-Requests-Remaining', resp.headers, 'no custom header')
        # *finishing* verification should decrement "left"
        self.assertEqual(resp.headers['X-Requests-Remaining'],
                         HEADER_FORMAT.format(1, now + LIMIT_PER_TIME, 2),
                         'incorrect header format or values, most likely '
                         'left is not 1')

        time.sleep(2)
        resp = session.put(API_ROOT + '/verify/deathly_hallows')
        # now that left < to, resets should still be LIMIT_PER_TIME after the
        # "now" that was *before* the last POST, rather than LIMIT_PER_TIME
        # after *this* "now". Also, this shouldn't decrement "left"
        self.assertEqual(resp.headers['X-Requests-Remaining'],
                         HEADER_FORMAT.format(1, now + LIMIT_PER_TIME, 2),
                         'incorrect header format or values, most likely '
                         'left is not 1 or resets changed since last request')

        # don't pretend it worked
        session.post(API_ROOT + '/debug/1')
        resp = session.post(API_ROOT + '/verify/deathly_hallows')
        self.assertEqual(resp.status_code, 403, "wait, didn't fail?")
        # even on failed verification, the API was called
        self.assertIn('X-Requests-Remaining', resp.headers,
                      'failed verification should still show ratelimits')
        # verify once more that "left" is now at 0
        self.assertEqual(resp.headers['X-Requests-Remaining'],
                         HEADER_FORMAT.format(0, now + LIMIT_PER_TIME, 2),
                         'incorrect header format or values, most likely '
                         'left is not 0 or resets changed since last request')

        # make sure I'm not banned lol
        #session.delete(API_ROOT + '/admin/bans/kenny2scratch')
        resp = session.post(API_ROOT + '/users/kenny2scratch/login')
        # this shouldn't 429 as it doesn't call Scratch
        self.assertNotEqual(resp.status_code, 429, 'login should not 429')
        # but it should include the header
        self.assertIn('X-Requests-Remaining', resp.headers,
                      'login missing custom header')
        # get this info for next test
        resets = re.search('resets=(\d+)', resp.headers['X-Requests-Remaining'])
        self.assertIsNotNone(resets, 'resets missing from header')
        resets = int(resets.group(1))

        resp = session.post(API_ROOT + '/users/kenny2scratch/finish-login')
        now = int(http2time(resp.headers['Date']))
        # this, however, should 429
        self.assertEqual(resp.status_code, 429)
        self.assertIn('Retry-After', resp.headers, '429 missing Retry-After')
        self.assertEqual(int(resp.headers['Retry-After']),
                         resets - now, 'wrong retry duration')

test_ban_expiry = int(time.time() + 1e6)

class TestBans(unittest.TestCase):
    """Test bans and their implementation."""

    @classmethod
    def setUpClass(cls):
        """All of these tests requires an admin session."""
        set_session(0)
        session.post(API_ROOT + '/debug/1')
        session.post(API_ROOT + '/admin/bans/permbanneduser',
                     json={'expiry': None})
        session.post(API_ROOT + '/admin/bans/tempbanneduser',
                     json={'expiry': test_ban_expiry})

    def test_get_all(self):
        """Test GET /admin/bans"""
        # using admin session: on
        session.post(API_ROOT + '/debug/1')

        resp = session.get(API_ROOT + '/admin/bans')
        # unless unauthenticated, response should be 200
        self.assertEqual(resp.status_code, 200, 'bans returned non-200')

        resp = resp.json()
        # response must implement structures
        self.assertIsInstance(resp, list, 'response not *list* of Bans')
        self.assertIsInstance(resp[0], Ban, 'response not list of *Ban*s')

        found_perm = False
        found_temp = False
        for ban in resp:
            if ban['username'] == 'permbanneduser':
                # perm ban is None expiry, make sure that persists
                self.assertIsNone(ban['expiry'],
                                 'permanent ban is not None expiry')
                found_perm = True
                if found_temp:
                    break
            if ban['username'] == 'tempbanneduser':
                # temp ban has existent expiry
                self.assertEqual(ban['expiry'], test_ban_expiry,
                                 'expiry is different from what was set')
                found_temp = True
                if found_perm:
                    break
        # make sure the bans are there in the first place
        self.assertTrue(found_perm, 'permanent ban was never set')
        self.assertTrue(found_temp, 'temporary ban was never set')

        # using admin session: off
        session.post(API_ROOT + '/debug/0')

        resp = session.get(API_ROOT + '/admin/bans')
        # unauthenticated must be 401
        self.assertEqual(resp.status_code, 401, 'unauthenticated MUST be 401')

    def test_get_one(self):
        """Test GET /admin/bans/{}"""
        # using admin session: on
        session.post(API_ROOT + '/debug/1')

        resp = session.get(API_ROOT + '/admin/bans/permbanneduser')
        # this was set earlier, so it should be 200
        self.assertEqual(resp.status_code, 200, 'bans returned non-200')

        resp = resp.json()
        # response must implement structure
        self.assertIsInstance(resp, PartialBan, 'response not PB')

        # setup set expiry to None, make sure that persists
        self.assertIsNone(resp['expiry'],
                         'expiry is different from what was set')

        resp = session.get(API_ROOT + '/admin/bans/deathly_hallows')
        # not set, not found
        self.assertEqual(resp.status_code, 404, 'not 404 for valid username')

        resp = session.get(API_ROOT + '/admin/bans/Impossible Username')
        # not valid, bad request
        self.assertEqual(resp.status_code, 400, 'not 400 for invalid username')

        # using admin session: off
        session.post(API_ROOT + '/debug/0')

        resp = session.get(API_ROOT + '/admin/bans/permbanneduser')
        # unauthenticated, unauthorized
        self.assertEqual(resp.status_code, 401, 'unauthenticated MUST be 401')

    def test_set_all(self):
        """Test PATCH /admin/bans"""
        # using admin session: on
        session.post(API_ROOT + '/debug/1')

        resp = session.patch(API_ROOT + '/admin/bans', json=[
            {'username': 'validusername', 'expiry': test_ban_expiry + 50},
            {'username': 'anothervalid', 'expiry': test_ban_expiry + 20},
        ])
        # success is a blank response
        self.assertEqual(resp.status_code, 204, 'unsuccessful PATCH')

        # make sure only those were set
        resp = session.get(API_ROOT + '/admin/bans/permbanneduser').json()
        self.assertIsNone(resp['expiry'], 'PATCH modified permbanneduser')

        # make sure those that were set were set right
        resp = session.get(API_ROOT + '/admin/bans/validusername')
        self.assertEqual(resp.status_code, 200, 'PATCH never set validusername')
        resp = resp.json()
        self.assertEqual(resp['expiry'], test_ban_expiry + 50, 'wrong expiry')

        # make sure invalid format errors too
        resp = session.patch(API_ROOT + '/admin/bans',
                             data={'youfellforit': 'fool!'})
        self.assertEqual(resp.status_code, 400, 'non-JSON never errored')

        # using admin session: off
        session.post(API_ROOT + '/debug/0')

        resp = session.patch(API_ROOT + '/admin/bans', json=[
            {'username': 'validusername', 'expiry': test_ban_expiry + 20},
            {'username': 'anothervalid', 'bans': test_ban_expiry + 50},
        ])
        # now more than ever, unauthenticated must be unauthorized
        self.assertEqual(resp.status_code, 401, 'unauthenticated MUST be 401')

    def test_set_one(self):
        """Test POST /admin/bans/{}"""
        # using admin session: on
        session.post(API_ROOT + '/debug/1')

        resp = session.post(API_ROOT + '/admin/bans/yetanother',
                            json={'expiry': test_ban_expiry + 20})
        # success is blank
        self.assertEqual(resp.status_code, 204, 'unsuccessful POST')

        # make sure it was set
        resp = session.get(API_ROOT + '/admin/bans/yetanother')
        self.assertEqual(resp.status_code, 200, 'POST never set yetanother')
        resp = resp.json()
        self.assertEqual(resp['expiry'], test_ban_expiry + 20, 'wrong expiry')

        # make sure invalid data errors
        resp = session.post(API_ROOT + '/admin/bans/yetanother',
                            data={'thundercross': 'splitattack!'})
        self.assertEqual(resp.status_code, 400, 'non-JSON never errored')
        resp = session.post(API_ROOT + '/admin/bans/yetanother',
                            json={'expiry': int(time.time()) - 2})
        self.assertEqual(resp.status_code, 400, 'expiry in past never errored')
        resp = session.post(API_ROOT + '/admin/bans/yetanother',
                            json={'expiry': 'max'})
        self.assertEqual(resp.status_code, 400, 'non-int expiry never errored')

        # using admin session: off
        session.post(API_ROOT + '/debug/0')

        resp = session.post(API_ROOT + '/admin/bans/yetanother',
                            json={'expiry': test_ban_expiry + 50})
        # you know the drill
        self.assertEqual(resp.status_code, 401, 'unauthenticated MUST be 401')

    def test_unban(self):
        """Test DELETE /admin/bans/{}"""
        # using admin session: on
        session.post(API_ROOT + '/debug/1')

        session.post(API_ROOT + '/admin/bans/yetanother',
                     json={'expiry': None})
        # unban the user
        resp = session.delete(API_ROOT + '/admin/bans/yetanother')
        # blank response on success
        self.assertEqual(resp.status_code, 204, 'unban unsuccessful')

        # using admin session: off
        session.post(API_ROOT + '/debug/0')

        resp = session.delete(API_ROOT + '/admin/bans/yetanother')
        # unauthenticated, unauthorized
        self.assertEqual(resp.status_code, 401, 'unauthenticated MUST be 401')

    def test_banned(self):
        """Test that bans work"""
        # using admin session: off
        session.post(API_ROOT + '/debug/0')

        resp = session.post(API_ROOT + '/users/permbanneduser/login')
        # banned users get 403ed
        self.assertEqual(resp.status_code, 403, 'banned did not 403')

class TestClient(unittest.TestCase):
    """Test miscellaneous endpoint(s)"""
    @classmethod
    def setUpClass(cls):
        """All of these tests requires an admin session."""
        set_session(0)
        session.post(API_ROOT + '/debug/1')

    def test_client(self):
        """Test /admin/client/{}"""
        resp = session.get(API_ROOT + '/admin/client/0')
        # 0 is registered when debug is on
        self.assertEqual(resp.status_code, 200, 'client was unsuccessful')

        resp = resp.json()
        # response must implement structure
        self.assertIsInstance(resp, Client, 'response was not Client object')

        # tokens are censored
        token = resp['token']
        token_len = len(token)
        self.assertEqual(token[TOKEN_CENSOR_LEN:],
                         '*' * (token_len - TOKEN_CENSOR_LEN),
                         f'token was not censored to {TOKEN_CENSOR_LEN} chars')
        for i in range(TOKEN_CENSOR_LEN):
            self.assertNotEqual(token[i], '*',
                                'asterisks should not appear in tokens')

class TestAuditLogging(unittest.TestCase):
    """Test audit-logging-related endpoints."""
    @classmethod
    def setUpClass(cls):
        """Do some stuff so that the logs are populated"""
        # bypass auth
        session.post(API_ROOT + '/debug/1')
        set_session(0)
        # add a ratelimit change
        session.post(API_ROOT + '/admin/ratelimits/deathly_hallows',
                     json={'ratelimit': 50})
        # add a ban
        session.post(API_ROOT + '/admin/bans/yetanother',
                     json={'expiry': None})
        # add an unban
        session.delete(API_ROOT + '/admin/bans/yetanother')

    def test_logs(self):
        """Test GET /usage"""
        resp = session.get(API_ROOT + '/admin/logs')
        # a well-formed request should always be a 200
        self.assertEqual(resp.status_code, 200, 'not 200')
        resp = resp.json()
        self.assertIsInstance(resp, list, 'not a *list* of AuditLogs')
        # response items must implement structure
        self.assertIsInstance(resp[0], AuditLog, 'not a list of *Log*s')

        # match entries with previous actions
        self.assertEqual(resp[0]['type'], 3, 'last log was not an unban')
        self.assertEqual(resp[0]['username'], 'kenny2scratch', 'wrong name')
        self.assertEqual(resp[0]['data'], '{"username": "yetanother"}',
                         'not target name')
        self.assertEqual(resp[1]['type'], 1, '2nd-last log was not a ban')
        self.assertEqual(resp[2]['type'], 2, '3rd-last log was not dRL')

    # no params test, that was already done in logs

    def test_log(self):
        """Test GET /usage/{}"""
        # skip ID validity, that was checked in /logs/{}

        # get specific log to fetch
        resp = session.get(API_ROOT + '/admin/logs').json()
        log = resp[-1]

        resp = session.get('%s/admin/logs/%s' % (API_ROOT, log['id']))
        # existent log should be success
        self.assertEqual(resp.status_code, 200, 'existent log not 200')

        resp = resp.json()
        # response must implement structure
        self.assertIsInstance(resp, AuditLog, 'response not AuditLog object')
        # check this is actually the same log
        self.assertEqual(resp, log, 'not the same log')

if __name__ == '__main__':
    unittest.main()
