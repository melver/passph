#
# Passph Unit Tests
# Author: Marco Elver
#

import unittest
import hashlib
import os

import passph

BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

class PassphTests(unittest.TestCase):
    def test_base_charlist_encode(self):
        self.assertEqual(
            passph.base_charlist_encode(b"The quick brown fox jumps over the lazy dog", BASE64_CHARS),
            "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw$$$$")

    def test_pbkdf2(self):
        # http://tools.ietf.org/html/rfc6070
        pbkdf2_test_vectors = [
                [[b"password", b"salt", 1, 20, hashlib.sha1],
                 [0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71,
                  0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06,
                  0x2f, 0xe0, 0x37, 0xa6]],
                [[b"password", b"salt", 2, 20, hashlib.sha1],
                 [0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c,
                  0xcd, 0x1e, 0xd9, 0x2a, 0xce, 0x1d, 0x41, 0xf0,
                  0xd8, 0xde, 0x89, 0x57]],
                [[b"password", b"salt", 4096, 20, hashlib.sha1],
                 [0x4b, 0x00, 0x79, 0x01, 0xb7, 0x65, 0x48, 0x9a,
                  0xbe, 0xad, 0x49, 0xd9, 0x26, 0xf7, 0x21, 0xd0,
                  0x65, 0xa4, 0x29, 0xc1]]
            ]

        for i in range(len(pbkdf2_test_vectors)):
            out = bytearray(passph.pbkdf2(*pbkdf2_test_vectors[i][0]))
            for j in range(len(out)):
                self.assertEqual(out[j], pbkdf2_test_vectors[i][1][j])

    def test_pre_hash(self):
        class Args:
            salt_url = None
            len_chars = 25
            iterations = 8000

        self.assertEqual(passph.pre_hash(b'', b'', Args)[:Args.len_chars], "v,Ddmn!2/Lc[*adw*tcw!5zaK")

        Args.len_chars = 50
        Args.iterations = 20000
        Args.salt_url = "file://" + os.path.normpath(os.path.join(os.path.abspath(__file__), os.path.pardir, os.path.pardir, os.path.pardir, ".gitignore"))
        self.assertEqual(passph.pre_hash(b'master', b'password', Args)[:Args.len_chars], "A4=m?tzmVWA]}{yap6WA?+A4#!88cd<9v6h7%k_ZBCx.(}lw}3")

if __name__ == "__main__":
    unittest.main()
