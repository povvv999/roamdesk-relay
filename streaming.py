"""Versioned ciphertext-only WebSocket transport; bounded, latest-frame delivery."""
import collections
import hashlib
import select
import socket
import struct
import time

try:
    from wsproto import WSConnection, ConnectionType
    from wsproto.events import AcceptConnection, Request, BytesMessage, TextMessage, Ping, Pong, CloseConnection
    from wsproto.utilities import RemoteProtocolError, LocalProtocolError
    AVAILABLE = True
except ImportError:
    AVAILABLE = False

from accounts import AccountDenied, AccountUnavailable

MAX_FRAME = 3 * 1024 * 1024
WINDOW = 4
WINDOW_BYTES = 2 * 1024 * 1024
SUBPROTOCOL = "roamdesk.frames.v1"


def handle(handler):
    parts = handler.path.strip('/').split('/')
    if len(parts) != 5 or parts[:2] != ['v1', 'sessions'] or parts[3] != 'stream':
        return False
    if not AVAILABLE:
        handler.reply(501); return True
    role = parts[4]
    if handler.command != 'GET' or role not in ('upload', 'view'):
        handler.reply(405); return True
    # No credentials in query strings, browser origins, or ambiguous HTTP bodies.
    if handler.headers.get('Origin') or handler.headers.get('Transfer-Encoding') or handler.headers.get_all('Content-Length', []) not in ([], ['0']):
        handler.reply(400); return True
    server = handler.server
    with server.lock:
        room = server.rooms.get(parts[2])
        if room is None or not handler.owns(room) or time.monotonic() - room.created >= 7 * 86400:
            handler.reply(404); return True
        token = room.host_token if role == 'upload' else room.viewer_token
        if not handler.authorized(token):
            handler.reply(403); return True
        if sum(1 for value in room.streams.values() if value == role) >= (1 if role == 'upload' else 2):
            handler.reply(409); return True
        room.streams[handler.connection] = role
    handler.close_connection = True
    try:
        run(handler, room, role)
    except (OSError, ValueError, RemoteProtocolError, LocalProtocolError):
        # Never log headers, account tokens, ciphertext or session identifiers.
        pass
    finally:
        with server.lock:
            room.streams.pop(handler.connection, None)
        handler.close_connection = True
    return True


def run(handler, room, role):
    ws = WSConnection(ConnectionType.SERVER)
    ws.initiate_upgrade_connection([(k.encode('ascii'), v.encode('latin-1')) for k, v in handler.headers.items()], handler.path)
    request = next((e for e in ws.events() if isinstance(e, Request)), None)
    if request is None or SUBPROTOCOL not in request.subprotocols:
        handler.reply(400); return
    sock = handler.connection
    sock.settimeout(2)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def send(event):
        sock.sendall(ws.send(event))

    send(AcceptConnection(subprotocol=SUBPROTOCOL))
    send(TextMessage(data='ready'))
    partial = bytearray()
    last_sent = 0
    last_host_sequence = 0
    pending = collections.OrderedDict()
    now = time.monotonic()
    started = now
    last_peer = last_ping = last_auth = now
    message_start = None
    while True:
        now = time.monotonic()
        with handler.server.lock:
            active = (handler.server.rooms.get(room.id) is room and handler.owns(room) and
                      now - room.created < 7 * 86400)
        if not active:
            send(CloseConnection(code=1008, reason='Session ended')); return
        if role == 'view' and now - max(room.last_frame, started) > 10:
            send(CloseConnection(code=1013, reason='Host stopped updating')); return
        if now - last_auth > 2:
            if not handler.server.allow_anonymous:
                try:
                    identity = handler.server.authenticator(handler.headers.get('X-Roamdesk-Account-Token', ''))
                    if identity != room.account:
                        raise AccountDenied()
                except (AccountDenied, AccountUnavailable):
                    send(CloseConnection(code=1008, reason='Sign in required')); return
            last_auth = now
        if now - last_peer > 15 or (message_start is not None and now - message_start > 5):
            send(CloseConnection(code=1008, reason='Stream timed out')); return
        if pending and now - next(iter(pending.values()))[1] > 2:
            send(CloseConnection(code=1013, reason='Viewer too slow')); return
        if now - last_ping > 5:
            send(Ping(payload=b'live')); last_ping = now
        if role == 'view' and len(pending) < WINDOW and sum(v[0] for v in pending.values()) < WINDOW_BYTES:
            with handler.server.lock:
                sequence, frame, stamp = room.frame_sequence, room.frame, room.last_frame
            if frame and sequence != last_sent and now - stamp < 10:
                send(BytesMessage(data=struct.pack('!Q', sequence) + frame))
                pending[sequence] = (len(frame), time.monotonic())
                last_sent = sequence
        ready, _, _ = select.select([sock], [], [], 0.02)
        if not ready:
            continue
        data = handler.rfile.read1(65536)
        if not data:
            return
        ws.receive_data(data)
        for event in ws.events():
            last_peer = time.monotonic()
            if isinstance(event, CloseConnection):
                send(event.response()); return
            if isinstance(event, Ping):
                send(event.response())
            elif isinstance(event, Pong):
                pass
            elif isinstance(event, TextMessage):
                if role != 'view' or not event.message_finished or len(event.data) > 32 or not event.data.startswith('ack:'):
                    send(CloseConnection(code=1008, reason='Invalid message')); return
                sequence = int(event.data[4:])
                if sequence not in pending:
                    send(CloseConnection(code=1008, reason='Invalid acknowledgement')); return
                del pending[sequence]
            elif isinstance(event, BytesMessage):
                if role != 'upload':
                    send(CloseConnection(code=1008, reason='Read only stream')); return
                if message_start is None:
                    message_start = time.monotonic()
                partial.extend(event.data)
                if len(partial) > MAX_FRAME + 8:
                    send(CloseConnection(code=1009, reason='Frame too large')); return
                if event.message_finished:
                    if len(partial) < 36:
                        send(CloseConnection(code=1008, reason='Invalid frame')); return
                    sequence = struct.unpack('!Q', partial[:8])[0]
                    if sequence <= last_host_sequence:
                        send(CloseConnection(code=1008, reason='Out of order frame')); return
                    frame = bytes(partial[8:]); partial.clear(); message_start = None
                    tag = '"' + hashlib.sha256(frame).hexdigest() + '"'
                    with handler.server.lock:
                        if handler.server.rooms.get(room.id) is not room:
                            return
                        room.frame = frame; room.frame_etag = tag
                        room.frame_sequence += 1; room.last_frame = time.monotonic()
                    last_host_sequence = sequence
                    send(TextMessage(data='ack:' + str(sequence)))
