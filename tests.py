"""Test actual API endpoints"""
import sys
import os
import unittest
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
        self.assertEqual(resp['code'], code, 'same PUT but not same code')

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
        session.post(API_ROOT + '/users/Deathly_Hallows/login')
        resp = session.post(API_ROOT + '/users/Deathly_Hallows/finish-login')
        resp = resp.json()
        self.assertFalse(resp['admin'], 'Deathly_Hallows should not be admin')

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

def do_dummy_actions():
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

class TestLogging(unittest.TestCase):
    """Test logging-related endpoints."""
    def test_logs(self):
        """Test GET /usage"""
        do_dummy_actions()

        # no need to pretend anything, logs are public
        session.post(API_ROOT + '/debug/0')

        resp = session.get(API_ROOT + '/usage')
        # a well-formed request should always be a 200
        self.assertEqual(resp.status_code, 200, 'not 200')
        resp = resp.json()
        self.assertIsInstance(resp, list, 'not a *list* of Logs')
        # response items must implement structure
        self.assertIsInstance(resp[0], Log, 'not a list of *Log*s')

        # match entries with previously actions
        self.assertEqual(resp[0]['log_type'], 4, 'last log was not invalidated')
        self.assertEqual(resp[0]['username'], 'kenny2scratch', 'wrong name')
        self.assertEqual(resp[1]['log_type'], 1, '2nd-last log was not started')
        self.assertEqual(resp[2]['log_type'], 2, '3rd-last log was not OK')

    def test_important_log_params(self):
        """Test GET /usage parameters"""
        do_dummy_actions()
        # debug not necessary for this
        session.post(API_ROOT + '/debug/0')

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
        do_dummy_actions()
        # debug not necessary
        session.post(API_ROOT + '/debug/0')

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
        self.assertEqual(resp, log, 'wrong log type')

if __name__ == '__main__':
    unittest.main()
