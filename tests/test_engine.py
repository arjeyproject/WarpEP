"""End-to-end scanner tests against a real WireGuard responder on loopback.

No network, no mocks of the protocol: a genuine Noise responder answers on
127.0.0.1 and the scanner has to find it, time it, and correctly write off the
ports that answer nothing.
"""

import socket
import struct
import threading
import unittest

from warpep.endpoints import Endpoint
from warpep.engine import EndpointResult, ScanConfig, Scanner, verify_endpoint
from warpep.wireguard import noise, transport


class FakeWarpResponder(threading.Thread):
    """A minimal WARP-like endpoint: valid handshakes, optional cookie mode."""

    daemon = True

    def __init__(self, static, mode="answer", loss_pattern=None):
        super().__init__()
        self.static = static
        self.mode = mode
        self.loss_pattern = list(loss_pattern or [])
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sock.settimeout(0.2)
        self._stop = threading.Event()
        self.seen = 0
        self.sessions = {}

    def run(self):
        while not self._stop.is_set():
            try:
                packet, peer = self.sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                return
            kind = noise.message_type(packet)
            if kind == noise.MSG_INITIATION:
                self.seen += 1
                if self.loss_pattern and not self.loss_pattern[(self.seen - 1) % len(self.loss_pattern)]:
                    continue
                if self.mode == "silent":
                    continue
                if self.mode == "garbage":
                    self.sock.sendto(b"\x02" + bytes(91), peer)
                    continue
                responder = noise.Responder(self.static)
                try:
                    peer_index, _ = responder.consume_initiation(packet)
                except noise.HandshakeError:
                    continue
                if self.mode == "cookie":
                    self.sock.sendto(
                        bytes([noise.MSG_COOKIE_REPLY]) + bytes(3) + struct.pack("<I", peer_index) + bytes(56),
                        peer,
                    )
                    continue
                response, keys = responder.response(peer_index)
                self.sessions[keys.sender_index] = keys
                self.sock.sendto(response, peer)
            elif kind == noise.MSG_DATA:
                receiver = struct.unpack("<I", packet[4:8])[0]
                keys = self.sessions.get(receiver)
                if keys is None:
                    continue
                try:
                    counter, payload = transport.open_packet(keys, packet)
                except Exception:
                    continue
                reply = self._echo_reply(payload)
                if reply:
                    self.sock.sendto(transport.seal(keys, counter, reply), peer)

    @staticmethod
    def _echo_reply(payload):
        if len(payload) < 28 or payload[9] != 1 or payload[20] != 8:
            return None
        header = bytearray(payload[:20])
        header[12:16], header[16:20] = payload[16:20], payload[12:16]
        icmp = bytearray(payload[20:])
        icmp[0] = 0  # echo reply
        icmp[2:4] = b"\x00\x00"
        icmp[2:4] = struct.pack(">H", transport._checksum(bytes(icmp)))
        return bytes(header) + bytes(icmp)

    def stop(self):
        self._stop.set()
        self.sock.close()


def free_udp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class ScannerAgainstLiveResponder(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = noise.Keypair.generate()
        cls.client = noise.Keypair.generate()
        cls.responder = FakeWarpResponder(cls.server)
        cls.responder.start()

    @classmethod
    def tearDownClass(cls):
        cls.responder.stop()

    def scanner(self, **kwargs):
        config = ScanConfig(timeout=0.5, rate=4000, pool_size=4, **kwargs)
        return Scanner(static=self.client, responder_public=self.server.public, config=config)

    def test_finds_the_live_endpoint(self):
        live = Endpoint("127.0.0.1", self.responder.port)
        results = self.scanner(probes=3).scan([live])
        self.assertEqual(len(results), 1)
        result = results[0]
        self.assertEqual(result.sent, 3)
        self.assertEqual(result.received, 3)
        self.assertEqual(result.loss, 0.0)
        self.assertTrue(result.alive)
        self.assertIsNotNone(result.avg)
        self.assertLess(result.avg, 500)

    def test_dead_port_is_reported_as_full_loss(self):
        dead = Endpoint("127.0.0.1", free_udp_port())
        (result,) = self.scanner(probes=2).scan([dead])
        self.assertEqual(result.received, 0)
        self.assertEqual(result.loss, 100.0)
        self.assertFalse(result.alive)
        self.assertIsNone(result.avg)

    def test_live_endpoint_sorts_above_dead_ones(self):
        live = Endpoint("127.0.0.1", self.responder.port)
        targets = [Endpoint("127.0.0.1", free_udp_port()) for _ in range(3)] + [live]
        results = self.scanner(probes=2).scan(targets)
        self.assertEqual(results[0].endpoint, live)

    def test_port_discovery_returns_only_open_ports(self):
        ports = [free_udp_port(), self.responder.port, free_udp_port()]
        found = self.scanner(probes=1).discover_ports(["127.0.0.1"], ports, sample=1)
        self.assertEqual(found, [self.responder.port])

    def test_many_targets_complete_without_leaking_probes(self):
        targets = [Endpoint("127.0.0.1", free_udp_port()) for _ in range(40)]
        targets.append(Endpoint("127.0.0.1", self.responder.port))
        results = self.scanner(probes=1, max_inflight=8).scan(targets)
        self.assertEqual(len(results), 41)
        self.assertTrue(all(r.sent == 1 for r in results))
        self.assertEqual(sum(1 for r in results if r.alive), 1)

    def test_tunnel_verification_carries_real_icmp(self):
        check = verify_endpoint(
            self.client,
            Endpoint("127.0.0.1", self.responder.port),
            responder_public=self.server.public,
            target_ip="162.159.192.1",
            echoes=2,
            timeout=1.5,
        )
        self.assertIsNone(check.error)
        self.assertTrue(check.ok, check.error)
        self.assertEqual(len(check.tunnel_rtts), 2)
        self.assertIsNotNone(check.handshake_ms)


class ScannerAgainstHostileEndpoints(unittest.TestCase):
    def setUp(self):
        self.server = noise.Keypair.generate()
        self.client = noise.Keypair.generate()

    def _scan(self, responder, probes=2):
        responder.start()
        self.addCleanup(responder.stop)
        config = ScanConfig(probes=probes, timeout=0.5, rate=4000, pool_size=2)
        scanner = Scanner(static=self.client, responder_public=self.server.public, config=config)
        return scanner.scan([Endpoint("127.0.0.1", responder.port)])[0]

    def test_garbage_replies_never_count_as_alive(self):
        result = self._scan(FakeWarpResponder(self.server, mode="garbage"))
        self.assertEqual(result.received, 0)
        self.assertFalse(result.alive)

    def test_cookie_replies_count_as_alive_but_not_as_latency(self):
        result = self._scan(FakeWarpResponder(self.server, mode="cookie"))
        self.assertEqual(result.received, 0)
        self.assertEqual(result.cookies, 2)
        self.assertTrue(result.alive)

    def test_partial_loss_is_measured(self):
        result = self._scan(FakeWarpResponder(self.server, loss_pattern=[1, 0]), probes=4)
        self.assertEqual(result.sent, 4)
        self.assertEqual(result.received, 2)
        self.assertAlmostEqual(result.loss, 50.0)

    def test_verify_reports_cookie_challenge(self):
        responder = FakeWarpResponder(self.server, mode="cookie")
        responder.start()
        self.addCleanup(responder.stop)
        check = verify_endpoint(
            self.client,
            Endpoint("127.0.0.1", responder.port),
            responder_public=self.server.public,
            timeout=1.0,
        )
        self.assertFalse(check.ok)
        self.assertIn("cookie", check.error)


class Scoring(unittest.TestCase):
    def _result(self, rtts, sent=3, cookies=0):
        r = EndpointResult(Endpoint("162.159.192.1", 2408), sent=sent, received=len(rtts), cookies=cookies)
        r.rtts = list(rtts)
        return r

    def test_lower_latency_scores_better(self):
        self.assertLess(self._result([20, 22, 21]).score, self._result([90, 95, 92]).score)

    def test_loss_outweighs_latency(self):
        lossy_fast = self._result([10])
        clean_slow = self._result([120, 125, 118])
        self.assertLess(clean_slow.score, lossy_fast.score)

    def test_dead_endpoints_score_infinite(self):
        self.assertEqual(self._result([]).score, float("inf"))

    def test_jitter_and_serialisation(self):
        result = self._result([10.0, 14.0, 12.0])
        self.assertAlmostEqual(result.jitter, 3.0)
        payload = result.as_dict()
        self.assertEqual(payload["endpoint"], "162.159.192.1:2408")
        self.assertEqual(payload["loss_percent"], 0.0)
        self.assertEqual(payload["best_ms"], 10.0)


if __name__ == "__main__":
    unittest.main()
