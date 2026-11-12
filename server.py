#!/usr/bin/env python3
"""Roamdesk development relay. Ciphertext only; put HTTPS in front for remote use."""
import base64
import collections
import hmac
import hashlib
import json
import os
import secrets
import socket
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pairing import handle as handle_pairing
from accounts import AccountAuthenticator, AccountDenied, AccountUnavailable

MAX_FRAME = 3 * 1024 * 1024
MAX_JSON = 32 * 1024
SESSION_TTL = 7 * 24 * 3600
COMMAND_TTL = 25


class Room:
    def __init__(self, owner=None, account=None):
        self.id = str(uuid.uuid4())
        self.owner = owner
        self.account = account
        self.host_token = secrets.token_urlsafe(32)
        self.viewer_token = secrets.token_urlsafe(32)
        self.created = time.monotonic()
        self.last_frame = 0.0
        self.frame = b""
        self.frame_etag = ""
        self.commands = collections.OrderedDict()
        self.seen = {}
        self.pairing = None


class RelayServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 32

    def __init__(self, address, admin_token, authenticator=None, allow_anonymous=False):
        if len(admin_token) < 32:
            raise ValueError("ROAMDESK_ADMIN_TOKEN must have at least 32 characters.")
        if allow_anonymous and address[0] not in ("127.0.0.1", "localhost", "::1"):
            raise ValueError("Anonymous transport tests must bind to loopback")
        super().__init__(address, Handler)
        self.authenticator = authenticator
        self.allow_anonymous = allow_anonymous
        self.admin_token = admin_token
        self.rooms = {}
        self.lock = threading.RLock()
        self.pair_attempts = {}
        self.pair_global = collections.deque()
        self.hosts = {}
        self.registration_attempts = collections.deque()

    def get_request(self):
        sock, address = super().get_request()
        sock.settimeout(10)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return sock, address


class Handler(BaseHTTPRequestHandler):
    server_version = "RoamdeskRelay/0.2.1"
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass  # Never log credentials, session paths, or payloads.

    def reply(self, status, value=None, binary=False, etag=None):
        # Snapshot the response while locked; socket writes happen after route() exits.
        data = value if binary else json.dumps(value or {}).encode()
        self.pending_response = (status, data, binary, etag)

    def flush_reply(self):
        status, value, binary, etag = self.pending_response
        data = value
        if status in (204, 304):
            data = b""
        self.send_response(status)
        self.send_header("Content-Type", "application/octet-stream" if binary else "application/json")
        self.send_header("Content-Length", str(len(data)))
        if etag:
            self.send_header("ETag", etag)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        # Only reuse connections whose request bodies were consumed completely.
        no_body = (not self.headers.get("Transfer-Encoding") and
                   self.headers.get_all("Content-Length", []) in ([], ["0"]))
        reusable = (status < 400 and not self.close_connection and
                    (no_body or self.body_consumed))
        self.close_connection = not reusable
        self.send_header("Connection", "keep-alive" if reusable else "close")
        self.end_headers()
        self.wfile.write(data)

    def read_body(self, maximum, binary=False):
        if self.headers.get("Transfer-Encoding"):
            raise ValueError("Chunked bodies are not accepted")
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) != 1:
            raise ValueError("Content-Length required")
        length = int(lengths[0])
        if not 0 <= length <= maximum:
            raise ValueError("Payload too large")
        data = self.rfile.read(length)
        if len(data) != length:
            raise ValueError("Incomplete payload")
        self.body_consumed = True
        return data if binary else json.loads(data)

    def authorized(self, expected):
        actual = self.headers.get("Authorization", "")
        return hmac.compare_digest(actual.encode(), ("Bearer " + expected).encode())

    def owns(self, room):
        return self.server.allow_anonymous or room.account == self.account_id

    def route(self):
        if self.path == "/health" and self.command == "GET":
            return self.reply(200, {"status": "ok", "protocol": 1, "version": "0.2.1"})
        self.account_id = None
        if not self.server.allow_anonymous:
            if self.server.authenticator is None:
                return self.reply(503, {"error": "Account service is not configured"})
            try:
                self.account_id = self.server.authenticator(self.headers.get("X-Roamdesk-Account-Token", ""))
            except AccountDenied:
                return self.reply(401, {"error": "Sign in required"})
            except AccountUnavailable:
                return self.reply(503, {"error": "Account service unavailable"})
        if handle_pairing(self):
            return
        with self.server.lock:
            now = time.monotonic()
            self.server.rooms = {key: room for key, room in self.server.rooms.items()
                                 if now - room.created < SESSION_TTL}
            if self.path == "/v1/hosts" and self.command == "POST":
                # Installation credentials are scoped to the verified account and Mac.
                self.server.hosts = {token: host for token, host in self.server.hosts.items() if now - host["created"] < 30 * 86400}
                while self.server.registration_attempts and now - self.server.registration_attempts[0][0] >= 3600:
                    self.server.registration_attempts.popleft()
                ip = self.client_address[0]
                if len(self.server.hosts) >= 1000 or len(self.server.registration_attempts) >= 120 or sum(1 for _, peer in self.server.registration_attempts if peer == ip) >= 12:
                    return self.reply(429, {"error": "Registration limit reached"})
                self.server.registration_attempts.append((now, ip))
                token = secrets.token_urlsafe(32)
                host = {"id": str(uuid.uuid4()), "created": now, "account": self.account_id}
                self.server.hosts[token] = host
                return self.reply(201, {"id": host["id"], "token": token})
            if self.path == "/v1/sessions" and self.command == "POST":
                raw_token = self.headers.get("Authorization", "").removeprefix("Bearer ")
                host = self.server.hosts.get(raw_token) if self.headers.get("Authorization", "").startswith("Bearer ") else None
                if host and (now - host["created"] >= 30 * 86400 or (not self.server.allow_anonymous and host["account"] != self.account_id)):
                    host = None
                if not self.authorized(self.server.admin_token) and host is None:
                    return self.reply(401, {"error": "Unauthorized"})
                if host and sum(1 for room in self.server.rooms.values() if room.owner == host["id"]) >= 3:
                    return self.reply(429, {"error": "Host session limit reached"})
                if len(self.server.rooms) >= 16:
                    return self.reply(429, {"error": "Session limit reached"})
                room = Room(owner=host["id"] if host else None, account=self.account_id)
                self.server.rooms[room.id] = room
                return self.reply(201, {"id": room.id, "hostToken": room.host_token, "viewerToken": room.viewer_token})

            parts = self.path.strip("/").split("/")
            if len(parts) not in (3, 4) or parts[:2] != ["v1", "sessions"]:
                return self.reply(404)
            room = self.server.rooms.get(parts[2])
            if room is None or not self.owns(room):
                return self.reply(404)
            operation = parts[3] if len(parts) == 4 else ""
            is_host = self.authorized(room.host_token)
            is_viewer = self.authorized(room.viewer_token)
            if not is_host and not is_viewer:
                return self.reply(401)
            role = {("DELETE", ""): "host", ("DELETE", "connection"): "viewer", ("PUT", "frame"): "host",
                    ("GET", "frame"): "viewer", ("GET", "commands"): "host",
                    ("POST", "commands"): "viewer", ("POST", "ack"): "host"}.get((self.command, operation))
            if role is None:
                return self.reply(405)
            if (role == "host" and not is_host) or (role == "viewer" and not is_viewer):
                return self.reply(403)
            # Read bodies outside the global lock so one slow peer cannot stall every room.
        body = None
        if self.command in ("PUT", "POST"):
            body = self.read_body(MAX_FRAME if operation == "frame" else MAX_JSON, binary=operation == "frame")
        with self.server.lock:
            if self.server.rooms.get(room.id) is not room:
                return self.reply(410)
            now = time.monotonic()
            room.commands = collections.OrderedDict((key, item) for key, item in room.commands.items()
                                                   if now - item[0] < COMMAND_TTL)
            room.seen = {key: stamp for key, stamp in room.seen.items() if now - stamp < 120}
            if self.command == "DELETE":
                del self.server.rooms[room.id]
                return self.reply(204)
            if operation == "frame":
                if self.command == "PUT":
                    if len(body) < 28:
                        return self.reply(400)
                    room.frame = body
                    room.frame_etag = '"' + hashlib.sha256(body).hexdigest() + '"'
                    room.last_frame = now
                    return self.reply(204)
                if not room.frame or now - room.last_frame > 10:
                    return self.reply(204)
                if self.headers.get("If-None-Match") == room.frame_etag:
                    return self.reply(304, etag=room.frame_etag)
                return self.reply(200, room.frame, binary=True, etag=room.frame_etag)
            if operation == "commands":
                if self.command == "GET":
                    return self.reply(200, {"commands": [item[1] for item in room.commands.values()]})
                if now - room.last_frame > 10:
                    return self.reply(409, {"error": "Host not sharing"})
                if not isinstance(body, dict) or set(body) != {"id", "payload"}:
                    return self.reply(400)
                command_id = body["id"]
                uuid.UUID(command_id)
                payload = base64.b64decode(body["payload"], validate=True)
                if not 28 <= len(payload) <= 16_384:
                    return self.reply(400)
                if command_id in room.seen:
                    return self.reply(202)
                if len(room.commands) >= 64 or len(room.seen) >= 2_000:
                    return self.reply(429)
                room.commands[command_id] = (now, body)
                room.seen[command_id] = now
                return self.reply(202)
            if operation == "ack":
                if not isinstance(body, dict) or not isinstance(body.get("ids"), list) or len(body["ids"]) > 64:
                    return self.reply(400)
                for identifier in body["ids"]:
                    if not isinstance(identifier, str):
                        return self.reply(400)
                    room.commands.pop(identifier, None)
                return self.reply(204)

    def handle_method(self):
        self.body_consumed = False
        self.pending_response = None
        try:
            try:
                self.route()
            except (ValueError, TypeError, KeyError, UnicodeError, TimeoutError):
                self.reply(400, {"error": "Invalid request"})
            if self.pending_response is not None:
                self.flush_reply()
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            self.close_connection = True

    do_GET = do_POST = do_PUT = do_DELETE = handle_method


if __name__ == "__main__":
    token = os.environ.get("ROAMDESK_ADMIN_TOKEN", "")
    auth_url = os.environ.get("ROAMDESK_AUTH_URL", "")
    public_key = os.environ.get("ROAMDESK_AUTH_PUBLISHABLE_KEY", "")
    auth = AccountAuthenticator(auth_url, public_key) if auth_url and public_key else None
    server = RelayServer((os.environ.get("ROAMDESK_BIND", "127.0.0.1"), int(os.environ.get("PORT", "8787"))), token, authenticator=auth)
    print(f"Roamdesk relay listening on {server.server_address[0]}:{server.server_address[1]}. HTTPS required for remote devices.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
