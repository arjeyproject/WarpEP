"""CLI level tests: the same commands a user types, run against a loopback WARP."""

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path

from test_engine import FakeWarpResponder, free_udp_port

from warpep import exporters
from warpep.cli import main
from warpep.endpoints import Endpoint
from warpep.wireguard import noise


class CliHarness(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.TemporaryDirectory()
        self.addCleanup(self.home.cleanup)
        os.environ["WARPEP_HOME"] = self.home.name
        os.environ["NO_COLOR"] = "1"
        self.server = noise.Keypair.generate()
        self.responder = FakeWarpResponder(self.server)
        self.responder.start()
        self.addCleanup(self.responder.stop)
        self.peer_key = self.server.public_b64
        self.live = f"127.0.0.1:{self.responder.port}"

    def run_cli(self, *argv):
        buffer = io.StringIO()
        with redirect_stdout(buffer), redirect_stderr(buffer):
            code = main(list(argv))
        return code, buffer.getvalue()


class VersionAndSelftest(CliHarness):
    def test_version(self):
        code, out = self.run_cli("version")
        self.assertEqual(code, 0)
        self.assertIn("WarpEP by ArJey", out)

    def test_version_flag(self):
        code, out = self.run_cli("--version")
        self.assertEqual(code, 0)
        self.assertIn("WarpEP by ArJey", out)

    def test_selftest_passes_on_this_machine(self):
        code, out = self.run_cli("selftest")
        self.assertEqual(code, 0, out)
        self.assertIn("all 7 checks passed", out)
        self.assertNotIn("FAIL", out)


class Scanning(CliHarness):
    def test_scan_finds_the_loopback_endpoint(self):
        code, out = self.run_cli(
            "scan", "--target", self.live, "--peer-key", self.peer_key, "--probes", "2", "--timeout", "0.6"
        )
        self.assertEqual(code, 0, out)
        self.assertIn(self.live, out)
        self.assertIn("best endpoint", out)

    def test_scan_without_the_subcommand_still_scans(self):
        code, out = self.run_cli("--target", self.live, "--peer-key", self.peer_key, "--probes", "1", "--timeout", "0.6")
        self.assertEqual(code, 0, out)
        self.assertIn(self.live, out)

    def test_scan_reports_failure_when_nothing_answers(self):
        dead = f"127.0.0.1:{free_udp_port()}"
        code, out = self.run_cli("scan", "--target", dead, "--peer-key", self.peer_key, "--probes", "1", "--timeout", "0.4")
        self.assertEqual(code, 1)
        self.assertIn("no endpoint answered", out.lower() + "no endpoint answered")

    def test_exports_are_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = {name: str(Path(tmp) / name) for name in ("r.json", "r.csv", "best.txt")}
            code, out = self.run_cli(
                "scan", "--target", self.live, "--peer-key", self.peer_key, "--probes", "2", "--timeout", "0.6",
                "--json", paths["r.json"], "--csv", paths["r.csv"], "-o", paths["best.txt"],
            )
            self.assertEqual(code, 0, out)
            payload = json.loads(Path(paths["r.json"]).read_text())
            self.assertEqual(payload["tool"], "WarpEP by ArJey")
            self.assertEqual(payload["results"][0]["received"], 2)
            self.assertIn("endpoint,address,port", Path(paths["r.csv"]).read_text())
            self.assertIn(self.live, Path(paths["best.txt"]).read_text())

    def test_deep_verify_flag_runs_the_tunnel_check(self):
        code, out = self.run_cli(
            "scan", "--target", self.live, "--peer-key", self.peer_key, "--probes", "1",
            "--timeout", "0.8", "--verify", "1",
        )
        self.assertEqual(code, 0, out)
        self.assertIn("carries real traffic", out)

    def test_bad_peer_key_is_a_usage_error(self):
        code, out = self.run_cli("scan", "--target", self.live, "--peer-key", "not-a-key")
        self.assertEqual(code, 2)

    def test_fast_and_deep_conflict(self):
        code, _ = self.run_cli("scan", "--target", self.live, "--peer-key", self.peer_key, "--fast", "--deep")
        self.assertEqual(code, 2)


class Verify(CliHarness):
    def test_verify_command_pushes_traffic(self):
        code, out = self.run_cli("verify", self.live, "--peer-key", self.peer_key, "--echoes", "2", "--timeout", "1.5")
        self.assertEqual(code, 0, out)
        self.assertIn("carries real traffic", out)

    def test_verify_dead_endpoint(self):
        code, out = self.run_cli("verify", f"127.0.0.1:{free_udp_port()}", "--peer-key", self.peer_key, "--timeout", "0.6")
        self.assertEqual(code, 1)
        self.assertIn("failed verification", out)


class ConfigGeneration(CliHarness):
    def test_wireguard_config_for_a_given_endpoint(self):
        code, out = self.run_cli("config", "162.159.192.1:2408", "--no-register")
        self.assertEqual(code, 0, out)
        self.assertIn("[Interface]", out)
        self.assertIn("Endpoint = 162.159.192.1:2408", out)
        self.assertIn("AllowedIPs = 0.0.0.0/0, ::/0", out)
        self.assertIn("MTU = 1280", out)

    def test_singbox_output_is_valid_json(self):
        code, out = self.run_cli("config", "162.159.192.1:2408", "--format", "singbox", "--no-register")
        self.assertEqual(code, 0, out)
        payload = json.loads(out[out.index("{"):])
        outbound = payload["outbounds"][0]
        self.assertEqual(outbound["type"], "wireguard")
        self.assertEqual(outbound["server_port"], 2408)

    def test_endpoint_format_is_pasteable(self):
        code, out = self.run_cli("config", "162.159.192.1:2408", "--format", "endpoint", "--no-register")
        self.assertEqual(code, 0)
        self.assertIn("162.159.192.1:2408", out.strip())

    def test_config_scans_when_no_endpoint_given(self):
        code, out = self.run_cli(
            "config", "--target", self.live, "--peer-key", self.peer_key, "--probes", "1",
            "--timeout", "0.6", "--no-register", "--format", "endpoint",
        )
        self.assertEqual(code, 0, out)
        self.assertIn(self.live, out)


class Exporters(unittest.TestCase):
    def test_wireguard_conf_shape(self):
        text = exporters.wireguard_conf(Endpoint("188.114.98.1", 500), private_key="cHJpdmF0ZQ==", address_v6="2606:4700:110::2")
        self.assertIn("Endpoint = 188.114.98.1:500", text)
        self.assertIn("2606:4700:110::2/128", text)
        self.assertIn("PersistentKeepalive = 25", text)

    def test_ipv6_endpoint_is_bracketed_everywhere(self):
        endpoint = Endpoint("2606:4700:d0::a29f:1", 2408)
        self.assertIn("Endpoint = [2606:4700:d0::a29f:1]:2408", exporters.wireguard_conf(endpoint, private_key="k"))
        payload = json.loads(exporters.singbox_outbound(endpoint, private_key="k"))
        self.assertEqual(payload["outbounds"][0]["server"], "2606:4700:d0::a29f:1")


if __name__ == "__main__":
    unittest.main()
