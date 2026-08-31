import struct
import unittest

from warpep.wireguard import noise


class HandshakeShape(unittest.TestCase):
    def setUp(self):
        self.server = noise.Keypair.generate()
        self.client = noise.Keypair.generate()
        self.identity = noise.PeerIdentity(self.client, self.server.public)

    def test_initiation_is_exactly_148_bytes(self):
        packet = noise.Initiator(self.identity).initiation()
        self.assertEqual(len(packet), noise.MESSAGE_INITIATION_SIZE)
        self.assertEqual(packet[0], noise.MSG_INITIATION)
        self.assertEqual(packet[1:4], b"\x00\x00\x00", "reserved bytes must be zero")
        self.assertEqual(packet[132:148], bytes(16), "mac2 must be blank without a cookie")

    def test_each_probe_uses_a_unique_sender_index(self):
        indices = set()
        for _ in range(50):
            packet = noise.Initiator(self.identity).initiation()
            indices.add(struct.unpack("<I", packet[4:8])[0])
        self.assertGreater(len(indices), 45)

    def test_timestamp_is_tai64n(self):
        stamp = noise.tai64n(1_700_000_000.5)
        self.assertEqual(len(stamp), 12)
        self.assertEqual(struct.unpack(">Q", stamp[:8])[0] - 0x400000000000000A, 1_700_000_000)


class FullHandshake(unittest.TestCase):
    """Prove protocol correctness offline: initiator against our own responder."""

    def setUp(self):
        self.server = noise.Keypair.generate()
        self.client = noise.Keypair.generate()
        self.identity = noise.PeerIdentity(self.client, self.server.public)

    def _complete(self):
        initiator = noise.Initiator(self.identity)
        responder = noise.Responder(self.server)
        peer_index, timestamp = responder.consume_initiation(initiator.initiation())
        self.assertEqual(peer_index, initiator.sender_index)
        self.assertEqual(len(timestamp), 12)
        self.assertEqual(responder.peer_static_public, self.client.public)
        response, server_keys = responder.response(peer_index)
        client_keys = initiator.consume_response(response)
        return client_keys, server_keys

    def test_transport_keys_agree(self):
        client_keys, server_keys = self._complete()
        self.assertEqual(client_keys.send_key, server_keys.receive_key)
        self.assertEqual(client_keys.receive_key, server_keys.send_key)
        self.assertNotEqual(client_keys.send_key, client_keys.receive_key)
        self.assertEqual(client_keys.receiver_index, server_keys.sender_index)
        self.assertEqual(server_keys.receiver_index, client_keys.sender_index)

    def test_keys_differ_between_sessions(self):
        first, _ = self._complete()
        second, _ = self._complete()
        self.assertNotEqual(first.send_key, second.send_key)

    def test_ephemeral_pool_reuse_still_completes(self):
        pooled = noise.Ephemeral(self.identity)
        for _ in range(3):
            initiator = noise.Initiator(self.identity, ephemeral=pooled)
            responder = noise.Responder(self.server)
            peer_index, _ = responder.consume_initiation(initiator.initiation())
            response, _ = responder.response(peer_index)
            self.assertTrue(initiator.consume_response(response).send_key)


class ResponseValidation(unittest.TestCase):
    def setUp(self):
        self.server = noise.Keypair.generate()
        self.client = noise.Keypair.generate()
        self.identity = noise.PeerIdentity(self.client, self.server.public)
        self.initiator = noise.Initiator(self.identity)
        self.initiator.initiation()

    def test_rejects_wrong_length(self):
        with self.assertRaises(noise.HandshakeError):
            self.initiator.consume_response(b"\x02" + bytes(40))

    def test_rejects_random_udp_noise(self):
        import os

        packet = bytearray(os.urandom(noise.MESSAGE_RESPONSE_SIZE))
        packet[0] = noise.MSG_RESPONSE
        packet[1:4] = bytes(3)
        packet[8:12] = struct.pack("<I", self.initiator.sender_index)
        with self.assertRaises(noise.HandshakeError):
            self.initiator.consume_response(bytes(packet))

    def test_rejects_response_for_another_session(self):
        responder = noise.Responder(self.server)
        other = noise.Initiator(self.identity)
        peer_index, _ = responder.consume_initiation(other.initiation())
        response, _ = responder.response(peer_index)
        with self.assertRaises(noise.HandshakeError):
            self.initiator.consume_response(response)

    def test_detects_cookie_reply(self):
        packet = bytes([noise.MSG_COOKIE_REPLY]) + bytes(63)
        with self.assertRaises(noise.CookieReply):
            self.initiator.consume_response(packet)


if __name__ == "__main__":
    unittest.main()
