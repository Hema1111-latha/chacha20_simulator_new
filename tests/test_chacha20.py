"""Run with:  python -m unittest discover tests -v"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from chacha20 import chacha20_block, chacha20_crypt, quarter_round  # noqa: E402


class ChaCha20Tests(unittest.TestCase):
    def test_quarter_round_rfc8439(self):
        # RFC 8439 section 2.1.1
        s = [0x11111111, 0x01020304, 0x9B8D6F43, 0x01234567]
        quarter_round(s, 0, 1, 2, 3)
        self.assertEqual(s, [0xEA2A92F4, 0xCB1CF8CE, 0x4581472E, 0x5881C4BB])

    def test_block_function_rfc8439(self):
        # RFC 8439 section 2.3.2
        key = bytes(range(32))
        nonce = bytes.fromhex("000000090000004a00000000")
        block, _ = chacha20_block(key, nonce, 1)
        self.assertEqual(block[:16].hex(), "10f1e7e4d13b5915500fdd1fa32071c4")

    def test_round_trip(self):
        key, nonce = os.urandom(32), os.urandom(12)
        msg = b"Hello, Information Security! " * 10
        self.assertEqual(chacha20_crypt(key, nonce, chacha20_crypt(key, nonce, msg)), msg)

    def test_matches_cryptography_library(self):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
        key, nonce = os.urandom(32), os.urandom(12)
        msg = os.urandom(300)
        lib = Cipher(algorithms.ChaCha20(key, (1).to_bytes(4, "little") + nonce),
                     mode=None).encryptor().update(msg)
        self.assertEqual(chacha20_crypt(key, nonce, msg, counter=1), lib)


if __name__ == "__main__":
    unittest.main()
