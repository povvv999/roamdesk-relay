import collections
import http.client
import json
import socket
import struct
import threading
import time
import unittest
from server import RelayServer
from accounts import AccountDenied
from wsproto import WSConnection, ConnectionType
from wsproto.events import Request, AcceptConnection, BytesMessage, TextMessage, CloseConnection, Ping


class Peer:
    def __init__(self, address, path, token, account='owner'):
        self.socket = socket.create_connection(address, timeout=2)
        self.socket.settimeout(2)
        self.ws = WSConnection(ConnectionType.CLIENT)
        self.events = collections.deque()
        self.partial = bytearray()
        headers = [(b'Authorization', ('Bearer ' + token).encode()), (b'X-Roamdesk-Account-Token', account.encode())]
        self.send(Request(host='localhost', target=path, extra_headers=headers, subprotocols=['roamdesk.frames.v1']))

    def send(self, event):
        self.socket.sendall(self.ws.send(event))

    def read(self):
        while True:
            while self.events:
                event = self.events.popleft()
                if isinstance(event, Ping):
                    self.send(event.response()); continue
                if isinstance(event, BytesMessage):
                    self.partial.extend(event.data)
                    if not event.message_finished:
                        continue
                    event = BytesMessage(data=bytes(self.partial)); self.partial.clear()
                return event
            data = self.socket.recv(65536)
            if not data:
                return None
            self.ws.receive_data(data); self.events.extend(self.ws.events())

    def ready(self):
        assert isinstance(self.read(), AcceptConnection)
        assert self.read().data == 'ready'
        return self

    def close(self):
        self.socket.close()


class StreamingTests(unittest.TestCase):
    def setUp(self):
        self.server = RelayServer(('127.0.0.1', 0), 'a' * 40, authenticator=lambda token: token if token in ('owner', 'other') else (_ for _ in ()).throw(AccountDenied()))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True); self.thread.start()
        c = http.client.HTTPConnection(*self.server.server_address)
        c.request('POST', '/v1/sessions', body=b'{}', headers={'Authorization': 'Bearer ' + 'a' * 40, 'X-Roamdesk-Account-Token': 'owner'})
        r = c.getresponse(); self.room = json.loads(r.read()); c.close()
        self.path = '/v1/sessions/' + self.room['id']
        self.peers = []

    def tearDown(self):
        for peer in self.peers:
            peer.close()
        self.server.shutdown(); self.server.server_close(); self.thread.join()

    def peer(self, role, token=None, account='owner'):
        p = Peer(self.server.server_address, self.path + '/stream/' + role, token or self.room['hostToken' if role == 'upload' else 'viewerToken'], account)
        self.peers.append(p); return p

    def upload(self, p, seq):
        p.send(BytesMessage(data=struct.pack('!Q', seq) + bytes([seq % 256]) * 40000))
        self.assertEqual(p.read().data, 'ack:' + str(seq))

    def test_push_bounded_window_and_latest_frame(self):
        host, viewer = self.peer('upload').ready(), self.peer('view').ready()
        for i in range(1, 5):
            self.upload(host, i)
            frame = viewer.read().data
            self.assertEqual(frame[8:], bytes([i]) * 40000)
        # Viewer has not acknowledged: later uploads must not pile up behind it.
        for i in range(5, 10):
            self.upload(host, i)
        viewer.socket.settimeout(0.1)
        with self.assertRaises(socket.timeout):
            viewer.read()
        viewer.socket.settimeout(2)
        viewer.send(TextMessage(data='ack:1'))
        newest = viewer.read().data
        self.assertEqual(struct.unpack('!Q', newest[:8])[0], 9)
        self.assertEqual(newest[8:], bytes([9]) * 40000)

    def test_account_and_role_are_enforced_at_upgrade(self):
        for p, expected in [(self.peer('view', account='other'), 404), (self.peer('view', token=self.room['hostToken']), 403), (self.peer('upload', token=self.room['viewerToken']), 403), (self.peer('view', account='invalid'), 401)]:
            self.assertEqual(p.read().status_code, expected)

    def test_viewer_cannot_upload_and_host_cannot_replay(self):
        viewer = self.peer('view').ready()
        viewer.send(BytesMessage(data=b'x' * 40))
        self.assertEqual(viewer.read().code, 1008)
        host = self.peer('upload').ready()
        self.upload(host, 1)
        host.send(BytesMessage(data=struct.pack('!Q', 1) + b'x' * 40))
        self.assertEqual(host.read().code, 1008)

    def test_delete_immediately_closes_stream_sockets(self):
        host, viewer = self.peer('upload').ready(), self.peer('view').ready()
        c = http.client.HTTPConnection(*self.server.server_address)
        c.request('DELETE', self.path, headers={'Authorization': 'Bearer ' + self.room['hostToken'], 'X-Roamdesk-Account-Token': 'owner'})
        r = c.getresponse(); self.assertEqual(r.status, 204); r.read(); c.close()
        self.assertIsNone(host.read()); self.assertIsNone(viewer.read())

    def test_account_expiration_closes_established_stream(self):
        host = self.peer('upload').ready()
        self.server.authenticator = lambda _: (_ for _ in ()).throw(AccountDenied())
        host.socket.settimeout(4)
        self.assertEqual(host.read().code, 1008)

    def test_fragmented_frame_size_is_bounded(self):
        host = self.peer('upload').ready()
        for _ in range(4):
            try:
                host.send(BytesMessage(data=b'x' * (1024 * 1024), message_finished=False))
            except (BrokenPipeError, ConnectionResetError):
                break
        self.assertEqual(host.read().code, 1009)


if __name__ == '__main__':
    unittest.main()
