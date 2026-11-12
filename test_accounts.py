import base64
import http.client
import io
import json
import threading
import unittest
import urllib.error
from accounts import AccountAuthenticator, AccountDenied, AccountUnavailable
from server import RelayServer


class AccountRelayTests(unittest.TestCase):
    def setUp(self):
        def authenticate(token):
            if token not in ('alice-session', 'bob-session'):
                raise AccountDenied()
            return token.split('-')[0]
        self.server = RelayServer(('127.0.0.1', 0), 'test-admin-' + 'a' * 32, authenticator=authenticate)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def request(self, method, path, account='', token='', body=None):
        connection = http.client.HTTPConnection(*self.server.server_address, timeout=3)
        if isinstance(body, dict):
            body = json.dumps(body).encode()
        connection.request(method, path, body=body, headers={'Authorization': 'Bearer ' + token, 'X-Roamdesk-Account-Token': account})
        response = connection.getresponse()
        result = response.status, response.read()
        connection.close()
        return result

    def test_requires_account_and_fails_closed_without_configuration(self):
        self.assertEqual(self.request('GET', '/health')[0], 200)
        self.assertEqual(self.request('POST', '/v1/hosts', body={})[0], 401)
        self.assertEqual(self.request('POST', '/v1/pairing/claim', body={})[0], 401)
        self.server.authenticator = None
        self.assertEqual(self.request('POST', '/v1/hosts', 'alice-session', body={})[0], 503)
        with self.assertRaises(ValueError):
            RelayServer(('0.0.0.0', 0), 'a' * 32, allow_anonymous=True)

    def test_other_account_cannot_use_stolen_device_tokens_or_claim_code(self):
        status, body = self.request('POST', '/v1/hosts', 'alice-session', body={})
        self.assertEqual(status, 201)
        host = json.loads(body)['token']
        self.assertEqual(self.request('POST', '/v1/sessions', 'bob-session', host, {})[0], 401)
        status, body = self.request('POST', '/v1/sessions', 'alice-session', host, {})
        self.assertEqual(status, 201)
        room = json.loads(body)
        path = '/v1/sessions/' + room['id']
        status, body = self.request('POST', path + '/pairing', 'alice-session', room['hostToken'], {})
        self.assertEqual(status, 201)
        claim = {'code': json.loads(body)['code'], 'name': 'Phone', 'publicKey': base64.b64encode(b'p' * 32).decode()}
        self.assertEqual(self.request('POST', '/v1/pairing/claim', 'bob-session', body=claim)[0], 404)
        # A wrong account must not consume the rightful owner's code.
        status, body = self.request('POST', '/v1/pairing/claim', 'alice-session', body=claim)
        self.assertEqual(status, 201)
        ticket = json.loads(body)
        poll = '/v1/pairing/requests/' + ticket['id']
        self.assertEqual(self.request('GET', poll, 'bob-session', ticket['token'])[0], 410)
        self.assertEqual(self.request('GET', poll, 'alice-session', ticket['token'])[0], 200)
        for method, suffix, token, body in [
            ('GET', '/pairing', room['hostToken'], None),
            ('PUT', '/frame', room['hostToken'], b'x' * 30),
            ('GET', '/frame', room['viewerToken'], None),
            ('POST', '/commands', room['viewerToken'], {}),
            ('DELETE', '', room['hostToken'], None),
            ('DELETE', '/connection', room['viewerToken'], None),
        ]:
            self.assertEqual(self.request(method, path + suffix, 'bob-session', token, body)[0], 404)
        self.assertEqual(self.request('PUT', path + '/frame', 'alice-session', room['hostToken'], b'x' * 30)[0], 204)
        self.assertEqual(self.request('GET', path + '/frame', 'alice-session', room['viewerToken']), (200, b'x' * 30))


class AuthenticatorTests(unittest.TestCase):
    def test_verified_identity_comes_from_service_and_cache_is_bounded(self):
        auth = AccountAuthenticator('https://auth.example', 'sb_publishable_test')
        identity = '57e15328-15d4-4c8e-a924-fec83e031612'
        class Opener:
            calls = 0
            def open(self, request, timeout):
                self.calls += 1
                assert request.full_url == 'https://auth.example/auth/v1/user'
                assert request.get_header('Apikey') == 'sb_publishable_test'
                return io.BytesIO(json.dumps({'id': identity, 'email_confirmed_at': '2026-01-01', 'user_metadata': {'id': 'untrusted'}}).encode())
        auth.opener = Opener()
        token = 'valid-session-token-12345'
        self.assertEqual(auth(token), identity)
        self.assertEqual(auth(token), identity)
        self.assertEqual(auth.opener.calls, 1)
        self.assertNotIn(token, auth.cache)
        for n in range(1030):
            auth(token + str(n))
        self.assertEqual(len(auth.cache), 1024)

    def test_rejects_unverified_anonymous_expired_and_unavailable(self):
        auth = AccountAuthenticator('https://auth.example', 'sb_publishable_test')
        class Opener:
            payload = {}
            status = 200
            def open(self, request, timeout):
                if self.status != 200:
                    raise urllib.error.HTTPError(request.full_url, self.status, 'test', {}, None)
                return io.BytesIO(json.dumps(self.payload).encode())
        opener = Opener(); auth.opener = opener
        for payload in [
            {'id': '57e15328-15d4-4c8e-a924-fec83e031612'},
            {'id': '57e15328-15d4-4c8e-a924-fec83e031612', 'email_confirmed_at': 'yes', 'is_anonymous': True},
        ]:
            opener.payload = payload
            with self.assertRaises(AccountDenied): auth('session-token-1234567890')
        opener.status = 401
        with self.assertRaises(AccountDenied): auth('session-token-1234567890')
        opener.status = 503
        with self.assertRaises(AccountUnavailable): auth('session-token-1234567890')
        with self.assertRaises(AccountDenied): auth('')
        with self.assertRaises(ValueError): AccountAuthenticator('http://auth.example', 'sb_publishable_test')
        with self.assertRaises(ValueError): AccountAuthenticator('https://auth.example', 'service_role_secret')

if __name__ == '__main__':
    unittest.main()
