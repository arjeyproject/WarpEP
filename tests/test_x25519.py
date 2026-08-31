import unittest

from warpep.wireguard import x25519


class RFC7748Vectors(unittest.TestCase):
    def test_scalar_mult_vector_1(self):
        scalar = bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
        u = bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
        want = bytes.fromhex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
        self.assertEqual(x25519.x25519(scalar, u), want)

    def test_scalar_mult_vector_2(self):
        scalar = bytes.fromhex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d")
        u = bytes.fromhex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493")
        want = bytes.fromhex("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")
        self.assertEqual(x25519.x25519(scalar, u), want)

    def test_diffie_hellman_section_6_1(self):
        alice_priv = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        alice_pub = bytes.fromhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        bob_priv = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        bob_pub = bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        want = bytes.fromhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

        self.assertEqual(x25519.public_key(alice_priv), alice_pub)
        self.assertEqual(x25519.public_key(bob_priv), bob_pub)
        self.assertEqual(x25519.shared_secret(alice_priv, bob_pub), want)
        self.assertEqual(x25519.shared_secret(bob_priv, alice_pub), want)

    def test_random_keypairs_agree(self):
        a = x25519.generate_private_key()
        b = x25519.generate_private_key()
        self.assertEqual(
            x25519.shared_secret(a, x25519.public_key(b)),
            x25519.shared_secret(b, x25519.public_key(a)),
        )


if __name__ == "__main__":
    unittest.main()
