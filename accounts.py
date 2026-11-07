"""Verify account tokens against managed Auth. Never trust client-supplied user IDs."""
import collections
import hashlib
import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

class AccountDenied(Exception):
    pass

class AccountUnavailable(Exception):
    pass

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

class AccountAuthenticator:
    def __init__(self, origin, publishable_key):
        parsed = urllib.parse.urlsplit(origin)
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ('', '/'):
            raise ValueError('ROAMDESK_AUTH_URL must be an HTTPS origin')
        if not publishable_key.startswith('sb_publishable_'):
            raise ValueError('Use a public sb_publishable_ key, never a service-role key')
        self.url = origin.rstrip('/') + '/auth/v1/user'
        self.key = publishable_key
        self.cache = collections.OrderedDict()
        self.lock = threading.Lock()
        self.opener = urllib.request.build_opener(NoRedirect)

    def __call__(self, token):
        if not isinstance(token, str) or not 20 <= len(token) <= 16384 or any(c.isspace() for c in token):
            raise AccountDenied()
        digest = hashlib.sha256(token.encode()).digest()
        now = time.monotonic()
        with self.lock:
            entry = self.cache.get(digest)
            if entry and now < entry[0]:
                return entry[1]
        request = urllib.request.Request(self.url, headers={'Authorization': 'Bearer ' + token, 'apikey': self.key, 'Accept': 'application/json'})
        try:
            with self.opener.open(request, timeout=5) as response:
                data = response.read(65537)
            if len(data) > 65536:
                raise AccountUnavailable()
            user = json.loads(data)
            identity = str(uuid.UUID(user['id']))
            if user.get('is_anonymous') or not user.get('email_confirmed_at'):
                raise AccountDenied()
        except urllib.error.HTTPError as error:
            status = error.code
            error.close()
            if status in (400, 401, 403, 404):
                raise AccountDenied() from None
            raise AccountUnavailable() from None
        except (urllib.error.URLError, TimeoutError, OSError, ValueError, KeyError, TypeError):
            raise AccountUnavailable() from None
        with self.lock:
            self.cache[digest] = (time.monotonic() + 10, identity)
            self.cache.move_to_end(digest)
            while len(self.cache) > 1024:
                self.cache.popitem(last=False)
        return identity
