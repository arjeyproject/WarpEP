import ipaddress
import random
import unittest

from warpep import endpoints


class Ports(unittest.TestCase):
    def test_default_is_primary(self):
        self.assertEqual(endpoints.parse_ports(None), list(endpoints.PRIMARY_PORTS))

    def test_2408_is_the_first_port_tried(self):
        self.assertEqual(endpoints.PRIMARY_PORTS[0], 2408)

    def test_parses_lists_ranges_and_keywords(self):
        self.assertEqual(endpoints.parse_ports(["2408,500"]), [2408, 500])
        self.assertEqual(endpoints.parse_ports(["500-503"]), [500, 501, 502, 503])
        self.assertEqual(endpoints.parse_ports(["all"]), list(endpoints.ALL_PORTS))

    def test_deduplicates_while_keeping_order(self):
        self.assertEqual(endpoints.parse_ports(["2408,500,2408"]), [2408, 500])

    def test_rejects_nonsense(self):
        for bad in ["0", "70000", "9-2"]:
            with self.assertRaises(ValueError):
                endpoints.parse_ports([bad])


class Prefixes(unittest.TestCase):
    def test_official_prefixes_are_valid_networks(self):
        for prefix in endpoints.IPV4_PREFIXES + endpoints.IPV6_PREFIXES:
            ipaddress.ip_network(prefix)

    def test_expansion_yields_unique_hosts(self):
        hosts = endpoints.expand_prefixes(["162.159.192.0/24"])
        self.assertEqual(len(hosts), 254)
        self.assertEqual(len(set(hosts)), 254)
        self.assertIn("162.159.192.1", hosts)

    def test_ipv6_expansion(self):
        hosts = endpoints.expand_prefixes(["2606:4700:d0::/64"])
        self.assertTrue(all(ipaddress.ip_address(h).version == 6 for h in hosts))
        self.assertIn("2606:4700:d0::a29f:1", hosts)

    def test_rejects_absurd_prefix(self):
        with self.assertRaises(ValueError):
            endpoints.expand_prefixes(["10.0.0.0/8"])

    def test_sampling_is_deterministic_with_a_seed(self):
        hosts = endpoints.expand_prefixes(["162.159.192.0/24"])
        a = endpoints.sample_addresses(hosts, 10, random.Random(7))
        b = endpoints.sample_addresses(hosts, 10, random.Random(7))
        self.assertEqual(a, b)
        self.assertEqual(len(a), 10)


class EndpointFormatting(unittest.TestCase):
    def test_ipv4_and_ipv6_rendering(self):
        self.assertEqual(str(endpoints.Endpoint("162.159.192.1", 2408)), "162.159.192.1:2408")
        self.assertEqual(str(endpoints.Endpoint("2606:4700:d0::a29f:1", 500)), "[2606:4700:d0::a29f:1]:500")

    def test_roundtrip_parse(self):
        for text in ["162.159.192.1:2408", "[2606:4700:d0::a29f:1]:500"]:
            self.assertEqual(str(endpoints.Endpoint.parse(text)), text)

    def test_build_matrix(self):
        built = endpoints.build_endpoints(["1.1.1.1", "2.2.2.2"], [500, 2408])
        self.assertEqual(len(built), 4)


if __name__ == "__main__":
    unittest.main()
