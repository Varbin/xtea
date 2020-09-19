"""
Tests if ciphertexts can be decrypted and collect performance data.

The tests do not validate the modes to work as specified.
"""

import unittest
import os

from xtea import MODE_CBC, MODE_CTR, MODE_ECB, MODE_OFB, MODE_CFB, XTEACipher
from xtea.counter import Counter

AMOUNT = 50

try:
    from time import perf_counter as clock
except ImportError:
    from time import clock


def _test_mode(mode):
    plain = os.urandom(56) * 8
    counter = Counter(os.urandom(8))
    key = os.urandom(16)
    iv = os.urandom(8)  # pylint: disable=invalid-name

    encrypter = XTEACipher(key, IV=iv,
                           counter=counter, mode=mode, segment_size=64)
    encrypted = encrypter.encrypt(plain)

    decrypter = XTEACipher(key, IV=iv,
                           counter=counter, mode=mode, segment_size=64)

    counter.reset()
    decrypted = decrypter.decrypt(encrypted)
    if plain != decrypted:
        raise AssertionError("Invalid decryption!")


class TestModes(unittest.TestCase):
    """
    Test the modes of operation and gather performance data.
    """

    @staticmethod
    def test_ecb():
        """Test and profile ECB mode of operation."""
        print("Testing ECB")

        start = clock()
        for _ in range(AMOUNT):
            _test_mode(MODE_ECB)
        end = clock()
        time = end - start
        print("Time: %s" % str(round(time, 3)))

    @staticmethod
    def test_cbc():
        """Test and profile CBC mode of operation."""
        print("Testing CBC")
        start = clock()

        for _ in range(AMOUNT):
            _test_mode(MODE_CBC)

        end = clock()
        time = end - start
        print("Time: %s" % str(round(time, 3)))

    @staticmethod
    def test_cfb():
        """Test and profile CFB mode of operation."""
        print("Testing CFB")
        start = clock()

        for _ in range(AMOUNT):
            _test_mode(MODE_CFB)

        end = clock()
        time = end - start
        print("Time: %s" % str(round(time, 3)))

    @staticmethod
    def test_ofb():
        """Test and profile OFB mode of operation."""
        print("Testing OFB")
        start = clock()

        for _ in range(AMOUNT):
            _test_mode(MODE_OFB)

        end = clock()
        time = end - start
        print("Time: %s" % str(round(time, 3)))

    @staticmethod
    def test_ctr():
        """Test and profile CTR mode of operation."""
        print("Testing CTR")
        start = clock()

        for _ in range(AMOUNT):
            _test_mode(MODE_CTR)

        end = clock()
        time = end - start
        print("Time: %s" % str(round(time, 3)))


if __name__ == "__main__":
    unittest.main()
