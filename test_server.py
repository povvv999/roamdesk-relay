import base64
import http.client
import json
import threading
import time
import unittest
import uuid
from server import RelayServer


class RelayTests(unittest.TestCase):
    def setUp(self):
        self.admin = "test-admin-" + "a" * 32
        self.server = RelayServer(("127.0.0.1", 0), self.admin, allow_anonymous=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def request(self, method, path, token="", body=None):
        connection = http.client.HTTPConnection(*self.server.server_address, timeout=3)
        if isinstance(body, dict):
            body = json.dumps(body).encode()
        connection.request(method, path, body=body, headers={"Authorization": "Bearer " + token})
        response = connection.getresponse()
        result = response.status, response.read()
        connection.close()
        return result

    def room(self):
        status, data = self.request("POST", "/v1/sessions", self.admin, {})
        self.assertEqual(status, 201)
        return json.loads(data)

    def test_frame_keepalive_and_reauthorization(self):
        room = self.room()
        path = '/v1/sessions/' + room['id'] + '/frame'
        frame = b'frame' * 100
        self.request('PUT', path, room['hostToken'], frame)
        connection = http.client.HTTPConnection(*self.server.server_address, timeout=3)
        connection.request('GET', path, headers={'Authorization': 'Bearer ' + room['viewerToken']})
        response = connection.getresponse()
        self.assertEqual(response.read(), frame)
        self.assertEqual(response.getheader('Connection'), 'keep-alive')
        sock = connection.sock
        connection.request('GET', path, headers={'Authorization': 'Bearer wrong'})
        response = connection.getresponse()
        self.assertEqual(response.status, 401)
        response.read()
        self.assertIsNotNone(sock)
        self.assertEqual(response.getheader('Connection'), 'close')
        connection.close()

    def test_mac_registers_without_an_admin_key_and_is_scoped(self):
        self.assertEqual(self.request("POST", "/v1/sessions", "unregistered", {})[0], 401)
        status, body = self.request("POST", "/v1/hosts", body={})
        self.assertEqual(status, 201)
        host = json.loads(body)
        rooms = []
        for _ in range(3):
            status, body = self.request("POST", "/v1/sessions", host["token"], {})
            self.assertEqual(status, 201)
            rooms.append(json.loads(body))
        self.assertEqual(self.request("POST", "/v1/sessions", host["token"], {})[0], 429)
        other = json.loads(self.request("POST", "/v1/hosts", body={})[1])
        path = "/v1/sessions/" + rooms[0]["id"]
        self.assertEqual(self.request("DELETE", path, other["token"])[0], 401)
        self.assertEqual(self.request("DELETE", path, rooms[0]["hostToken"])[0], 204)
        self.assertEqual(self.request("POST", "/v1/sessions", host["token"], {})[0], 201)
        for _ in range(10):
            self.assertEqual(self.request("POST", "/v1/hosts", body={})[0], 201)
        self.assertEqual(self.request("POST", "/v1/hosts", body={})[0], 429)

    def test_keepalive_respects_close_and_unread_body(self):
        for headers, body in [({"Connection": "close"}, None), ({}, b"unread")]:
            connection = http.client.HTTPConnection(*self.server.server_address, timeout=3)
            connection.request("GET", "/health", body=body, headers=headers)
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            self.assertEqual(response.getheader("Connection"), "close")
            response.read()
            connection.close()

    def test_conditional_frames_recheck_role_and_revocation(self):
        room = self.room()
        path = "/v1/sessions/" + room["id"]
        self.request("PUT", path + "/frame", room["hostToken"], b"frame" * 100)
        connection = http.client.HTTPConnection(*self.server.server_address, timeout=3)
        headers = {"Authorization": "Bearer " + room["viewerToken"]}
        connection.request("GET", path + "/frame", headers=headers)
        response = connection.getresponse()
        tag = response.getheader("ETag")
        self.assertTrue(tag)
        response.read()
        headers["If-None-Match"] = tag
        connection.request("GET", path + "/frame", headers=headers)
        response = connection.getresponse()
        self.assertEqual(response.status, 304)
        self.assertEqual(response.read(), b"")
        headers["Authorization"] = "Bearer " + room["hostToken"]
        connection.request("GET", path + "/frame", headers=headers)
        response = connection.getresponse()
        self.assertEqual(response.status, 403)
        response.read()
        self.request("DELETE", path, room["hostToken"])
        headers["Authorization"] = "Bearer " + room["viewerToken"]
        connection.request("GET", path + "/frame", headers=headers)
        response = connection.getresponse()
        self.assertEqual(response.status, 404)
        response.read()
        connection.close()

    def test_roles_and_revocation(self):
        self.assertEqual(self.request("POST", "/v1/sessions", "wrong", {})[0], 401)
        room = self.room()
        path = "/v1/sessions/" + room["id"]
        frame = b"encrypted-frame" * 10
        self.assertEqual(self.request("PUT", path + "/frame", room["viewerToken"], frame)[0], 403)
        self.assertEqual(self.request("PUT", path + "/frame", room["hostToken"], frame)[0], 204)
        self.assertEqual(self.request("GET", path + "/frame", room["viewerToken"]), (200, frame))
        self.assertEqual(self.request("GET", path + "/commands", room["viewerToken"])[0], 403)
        self.assertEqual(self.request("DELETE", path, room["viewerToken"])[0], 403)
        self.assertEqual(self.request("DELETE", path, room["hostToken"])[0], 204)
        self.assertEqual(self.request("GET", path + "/frame", room["viewerToken"])[0], 404)

    def test_phone_disconnect_revokes_both_roles_and_queued_actions(self):
        room = self.room()
        path = "/v1/sessions/" + room["id"]
        self.request("PUT", path + "/frame", room["hostToken"], b"frame" * 10)
        command = {"id": str(uuid.uuid4()), "payload": base64.b64encode(b"ciphertext" * 4).decode()}
        self.request("POST", path + "/commands", room["viewerToken"], command)
        self.assertEqual(self.request("DELETE", path + "/connection", "wrong")[0], 401)
        self.assertEqual(self.request("DELETE", path + "/connection", room["hostToken"])[0], 403)
        self.assertEqual(self.request("DELETE", path + "/connection", room["viewerToken"])[0], 204)
        self.assertNotIn(room["id"], self.server.rooms)
        self.assertEqual(self.request("GET", path + "/commands", room["hostToken"])[0], 404)
        self.assertEqual(self.request("GET", path + "/frame", room["viewerToken"])[0], 404)
        self.assertEqual(self.request("POST", path + "/commands", room["viewerToken"], command)[0], 404)

    def test_command_delivery_ack_and_deduplication(self):
        room = self.room()
        path = "/v1/sessions/" + room["id"]
        command = {"id": str(uuid.uuid4()), "payload": base64.b64encode(b"opaque ciphertext" * 4).decode()}
        self.assertEqual(self.request("POST", path + "/commands", room["viewerToken"], command)[0], 409)
        self.request("PUT", path + "/frame", room["hostToken"], b"frame" * 10)
        for _ in range(2):
            self.assertEqual(self.request("POST", path + "/commands", room["viewerToken"], command)[0], 202)
        for _ in range(2):  # Polling must not silently consume a command before an acknowledgement.
            status, data = self.request("GET", path + "/commands", room["hostToken"])
            self.assertEqual(json.loads(data)["commands"], [command])
        self.request("POST", path + "/ack", room["hostToken"], {"ids": [command["id"]]})
        self.request("POST", path + "/commands", room["viewerToken"], command)
        self.assertEqual(json.loads(self.request("GET", path + "/commands", room["hostToken"])[1])["commands"], [])

    def test_stale_frames_and_commands_expire(self):
        room = self.room()
        path = "/v1/sessions/" + room["id"]
        self.request("PUT", path + "/frame", room["hostToken"], b"frame" * 10)
        command = {"id": str(uuid.uuid4()), "payload": base64.b64encode(b"ciphertext" * 4).decode()}
        self.request("POST", path + "/commands", room["viewerToken"], command)
        with self.server.lock:
            internal = self.server.rooms[room["id"]]
            internal.last_frame = time.monotonic() - 11
            internal.commands[command["id"]] = (time.monotonic() - 26, command)
        self.assertEqual(self.request("GET", path + "/frame", room["viewerToken"])[0], 204)
        self.assertEqual(json.loads(self.request("GET", path + "/commands", room["hostToken"])[1])["commands"], [])

    def test_malformed_and_cross_session_requests(self):
        first, second = self.room(), self.room()
        path = "/v1/sessions/" + first["id"]
        self.assertEqual(self.request("GET", path + "/frame", second["viewerToken"])[0], 401)
        self.request("PUT", path + "/frame", first["hostToken"], b"frame" * 10)
        self.assertEqual(self.request("POST", path + "/commands", first["viewerToken"], {"id": "bad", "payload": "bad"})[0], 400)
        self.assertEqual(self.request("POST", path + "/ack", first["hostToken"], {"ids": [{}]})[0], 400)

    def test_code_pairing_requires_host_approval_and_is_single_use(self):
        room = self.room()
        path = "/v1/sessions/" + room["id"]
        self.assertEqual(self.request("POST", path + "/pairing", room["viewerToken"], {})[0], 403)
        status, body = self.request("POST", path + "/pairing", room["hostToken"], {})
        invite = json.loads(body)
        self.assertEqual(status, 201)
        self.assertEqual(invite["expiresIn"], 300)
        self.assertEqual(len(invite["code"].replace(" ", "")), 8)
        self.assertTrue(all(char in "0123456789" for char in invite["code"].replace(" ", "")))
        claim = {"code": invite["code"], "name": "Test iPhone", "publicKey": base64.b64encode(b"p" * 32).decode()}
        status, body = self.request("POST", "/v1/pairing/claim", body=claim)
        self.assertEqual(status, 201)
        ticket = json.loads(body)
        self.assertEqual(self.request("POST", "/v1/pairing/claim", body=claim)[0], 404)
        poll = "/v1/pairing/requests/" + ticket["id"]
        self.assertEqual(self.request("GET", poll, "wrong")[0], 401)
        pending = json.loads(self.request("GET", poll, ticket["token"])[1])
        self.assertEqual(pending["status"], "waiting")
        self.assertIsNone(pending["payload"])
        key = {"requestId": ticket["id"], "publicKey": base64.b64encode(b"m" * 32).decode()}
        self.assertEqual(self.request("POST", path + "/pairing-key", room["hostToken"], key)[0], 204)
        approval = {"requestId": ticket["id"], "payload": base64.b64encode(b"sealedcredentials" * 3).decode()}
        self.assertEqual(self.request("POST", path + "/pairing-approve", room["viewerToken"], approval)[0], 403)
        for _ in range(2):
            self.assertEqual(self.request("POST", path + "/pairing-approve", room["hostToken"], approval)[0], 204)
        result = json.loads(self.request("GET", poll, ticket["token"])[1])
        self.assertEqual(result["status"], "approved")
        self.assertEqual(result["payload"], approval["payload"])
        self.request("DELETE", path, room["hostToken"])
        self.assertEqual(self.request("GET", poll, ticket["token"])[0], 410)

    def test_code_expiry_decline_and_guess_limit(self):
        room = self.room()
        path = "/v1/sessions/" + room["id"]
        invite = json.loads(self.request("POST", path + "/pairing", room["hostToken"], {})[1])
        claim = {"code": invite["code"], "name": "Phone", "publicKey": base64.b64encode(b"p" * 32).decode()}
        with self.server.lock:
            self.server.rooms[room["id"]].pairing["expires"] = time.monotonic() - 1
        self.assertEqual(self.request("POST", "/v1/pairing/claim", body=claim)[0], 404)
        invite = json.loads(self.request("POST", path + "/pairing", room["hostToken"], {})[1])
        claim["code"] = invite["code"]
        ticket = json.loads(self.request("POST", "/v1/pairing/claim", body=claim)[1])
        self.assertEqual(self.request("POST", path + "/pairing-deny", room["hostToken"], {"requestId": ticket["id"]})[0], 204)
        result = json.loads(self.request("GET", "/v1/pairing/requests/" + ticket["id"], ticket["token"])[1])
        self.assertEqual(result["status"], "denied")
        self.assertIsNone(result["payload"])
        for _ in range(10):
            self.request("POST", "/v1/pairing/claim", body=claim)
        self.assertEqual(self.request("POST", "/v1/pairing/claim", body=claim)[0], 429)


if __name__ == "__main__":
    unittest.main()
