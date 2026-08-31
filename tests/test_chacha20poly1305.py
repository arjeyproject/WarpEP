import unittest

from warpep.wireguard import chacha20poly1305 as aead


class RFC8439Vectors(unittest.TestCase):
    def test_chacha20_block_function(self):
        key = bytes(range(32))
        nonce = bytes.fromhex("000000090000004a00000000")
        block = aead.chacha20_block(key, 1, nonce)
        self.assertEqual(
            block.hex(),
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
            "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e",
        )

    def test_poly1305_vector(self):
        key = bytes.fromhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
        mac = aead.poly1305_mac(key, b"Cryptographic Forum Research Group")
        self.assertEqual(mac.hex(), "a8061dc1305136c6c22b8baf0c0127a9")

    def test_aead_encrypt_matches_rfc(self):
        key = bytes.fromhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
        nonce = bytes.fromhex("070000004041424344454647")
        aad_bytes = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
        plaintext = (
            b"Ladies and Gentlemen of the class of '99: If I could offer you "
            b"only one tip for the future, sunscreen would be it."
        )
        sealed = aead.encrypt(key, nonce, plaintext, aad_bytes)
        self.assertEqual(
            sealed[:-16].hex(),
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
            "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
            "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
            "3ff4def08e4b7a9de576d26586cec64b6116",
        )
        self.assertEqual(sealed[-16:].hex(), "1ae10b594f09e26a7e902ecbd0600691")
        self.assertEqual(aead.decrypt(key, nonce, sealed, aad_bytes), plaintext)

    def test_decrypt_rejects_tampering(self):
        key = bytes(32)
        nonce = bytes(12)
        sealed = bytearray(aead.encrypt(key, nonce, b"warpep", b"ad"))
        sealed[0] ^= 0x01
        with self.assertRaises(aead.InvalidTag):
            aead.decrypt(key, nonce, bytes(sealed), b"ad")

    def test_empty_plaintext_roundtrip(self):
        key = bytes(range(32))
        nonce = bytes(range(12))
        sealed = aead.encrypt(key, nonce, b"", b"header")
        self.assertEqual(len(sealed), 16)
        self.assertEqual(aead.decrypt(key, nonce, sealed, b"header"), b"")


if __name__ == "__main__":
    unittest.main()
