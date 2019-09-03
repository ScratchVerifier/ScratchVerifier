"""Test actual API endpoints"""
import sys
import os
import unittest
import requests
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))
from responses import *

API_ROOT = 'http://localhost:8888'
session = requests.session()

class TestApi(unittest.TestCase):
    """Test actual API endpoints."""
    def test_start(self):
        """Test PUT /verify/{}"""
        session.post(API_ROOT + '/debug/1')
        resp = session.put(API_ROOT + '/verify/Kenny2scratch')
        self.assertEqual(resp.status_code, 200, 'not HTTP 200')
        resp = resp.json()
        self.assertIsInstance(resp, Verification, 'not Verification')
        code = resp['code']
        resp = session.put(API_ROOT + '/verify/Kenny2scratch').json()
        self.assertEqual(resp['code'], code, 'same PUT but not same code')
        resp = session.put(API_ROOT + '/verify/Impossible Username')
        self.assertEqual(resp.status_code, 400, 'not HTTP 400 on invalid name')
        session.post(API_ROOT + '/debug/0')
        resp = session.put(API_ROOT + '/verify/Kenny2scratch')
        self.assertEqual(resp.status_code, 401, 'not HTTP 401 on missing auth')

    def test_end(self):
        """Test POST /verify/{}"""
        session.post(API_ROOT + '/debug/3')
        session.put(API_ROOT + '/verify/Kenny2scratch')
        resp = session.post(API_ROOT + '/verify/Kenny2scratch')
        self.assertEqual(resp.status_code, 204, 'not HTTP 204 on success')
        session.post(API_ROOT + '/debug/1')
        session.put(API_ROOT + '/verify/Kenny2scratch')
        resp = session.post(API_ROOT + '/verify/Kenny2scratch')
        self.assertEqual(resp.status_code, 403, 'not HTTP 403 on failure')
        resp = session.post(API_ROOT + '/verify/Kenny2scratch')
        self.assertEqual(resp.status_code, 404, 'not HTTP 404 without start')

    def test_cancel(self):
        """Test DELETE /verify/{}"""
        session.post(API_ROOT + '/debug/1')
        session.put(API_ROOT + '/verify/Kenny2scratch')
        resp = session.delete(API_ROOT + '/verify/Kenny2scratch')
        self.assertEqual(resp.status_code, 204, 'not HTTP 204 on success')

class TestLogin(unittest.TestCase):
    """Test the login and registration flow."""
    def test_login(self):
        """Test POST /users/{}/login"""
        session.post(API_ROOT + '/debug/1')
        resp = session.post(API_ROOT + '/users/Kenny2scratch/login')
        self.assertEqual(resp.status_code, 200, 'not HTTP 200')
        resp = resp.json()
        self.assertIsInstance(resp, Verification, 'not Verification')
        resp = session.post(API_ROOT + '/users/Impossible Username/login')
        self.assertEqual(resp.status_code, 400, 'not HTTP 400 on invalid name')

    def test_finish_login(self):
        """Test POST /users/{}/finish-login"""
        session.post(API_ROOT + '/debug/3')
        session.post(API_ROOT + '/users/Kenny2scratch/login')
        resp = session.post(API_ROOT + '/users/Kenny2scratch/finish-login')
        self.assertEqual(resp.status_code, 200, 'not HTTP 200')
        resp = resp.json()
        self.assertIsInstance(resp, Session, 'not Session')
        session.post(API_ROOT + '/debug/1')
        session.post(API_ROOT + '/users/Kenny2scratch/login')
        resp = session.post(API_ROOT + '/users/Kenny2scratch/finish-login')
        self.assertEqual(resp.status_code, 401, 'not HTTP 401 on failure')
        resp = session.post(API_ROOT + '/users/Kenny2scratch/finish-login')
        self.assertEqual(resp.status_code, 404, 'not HTTP 404 without start')

    def test_get_client(self):
        """Test GET /session/{}"""
        session.post(API_ROOT + '/debug/1')
        resp = session.get(API_ROOT + '/session/0')
        self.assertEqual(resp.status_code, 200, 'not 200')
        resp = resp.json()
        self.assertIsInstance(resp, User, 'not User')
        resp = session.get(API_ROOT + '/session/1')
        self.assertEqual(resp.status_code, 404, 'not 404 for unregistered client')
        session.post(API_ROOT + '/debug/0')
        resp = session.get(API_ROOT + '/session/1')
        self.assertEqual(resp.status_code, 401, 'not 401 on missing auth')

    def test_put_client(self):
        """Test PUT /session/{}"""
        session.post(API_ROOT + '/debug/1')
        resp = session.put(API_ROOT + '/session/1')
        self.assertEqual(resp.status_code, 200, 'not 200')
        resp = resp.json()
        self.assertIsInstance(resp, User, 'not User')
        resp = session.put(API_ROOT + '/session/0')
        self.assertEqual(resp.status_code, 409, 'not 409 on existing client')
        session.post(API_ROOT + '/debug/0')
        resp = session.put(API_ROOT + '/session/1')
        self.assertEqual(resp.status_code, 401, 'not 401 on missing auth')

    def test_patch_client(self):
        """Test PATCH /session/{}"""
        session.post(API_ROOT + '/debug/1')
        resp = session.patch(API_ROOT + '/session/0')
        self.assertEqual(resp.status_code, 200, 'not 200')
        resp = resp.json()
        self.assertIsInstance(resp, User, 'not User')
        session.post(API_ROOT + '/debug/0')
        resp = session.patch(API_ROOT + '/session/1')
        self.assertEqual(resp.status_code, 401, 'not 401 on missing auth')

    def test_delete_client(self):
        """Test DELETE /session/{}"""
        session.post(API_ROOT + '/debug/1')
        resp = session.delete(API_ROOT + '/session/0')
        self.assertEqual(resp.status_code, 204, 'not 204 on success')
        session.post(API_ROOT + '/debug/0')
        resp = session.delete(API_ROOT + '/session/1')
        self.assertEqual(resp.status_code, 401, 'not 401 on missing auth')

class TestLogging(unittest.TestCase):
    """Test logging-related endpoints."""
    def test_logs(self):
        """Test GET /usage"""
        session.post(API_ROOT + '/debug/3')
        session.put(API_ROOT + '/verify/Kenny2scratch')
        session.post(API_ROOT + '/verify/Kenny2scratch')
        session.post(API_ROOT + '/debug/1')
        session.put(API_ROOT + '/verify/Kenny2scratch')
        session.delete(API_ROOT + '/verify/Kenny2scratch')
        session.post(API_ROOT + '/debug/0')
        resp = session.get(API_ROOT + '/usage', params={'limit': 600})
        self.assertEqual(resp.status_code, 403, 'not 403 on big limit')
        resp = session.get(API_ROOT + '/usage')
        self.assertEqual(resp.status_code, 200, 'not 200')
        resp = resp.json()
        self.assertIsInstance(resp, list, 'not a *list* of Logs')
        self.assertIsInstance(resp[0], Log, 'not a list of *Log*s')
        self.assertEqual(resp[0]['log_type'], 4, 'last log was not invalidated')
        self.assertEqual(resp[0]['username'], 'kenny2scratch', 'wrong name')
        self.assertEqual(resp[1]['log_type'], 1, '2nd-last log was not started')
        self.assertEqual(resp[2]['log_type'], 2, '3rd-last log was not OK')

    def test_log(self):
        """Test GET /usage/{}"""
        session.post(API_ROOT + '/debug/1')
        session.put(API_ROOT + '/verify/Kenny2scratch')
        session.post(API_ROOT + '/debug/0')
        resp = session.get(API_ROOT + '/usage/-1')
        self.assertEqual(resp.status_code, 404, 'not 404 on nonexistent log')
        resp = session.get(API_ROOT + '/usage').json()
        log_id = resp[-1]['log_id']
        resp = session.get('%s/usage/%s' % (API_ROOT, log_id))
        self.assertEqual(resp.status_code, 200, 'not 200')
        resp = resp.json()
        self.assertIsInstance(resp, Log, 'not Log')
        self.assertEqual(resp['log_type'], 1, 'wrong log type')

if __name__ == '__main__':
    unittest.main()
