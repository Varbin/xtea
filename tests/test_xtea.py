import unittest
import os

import time

from xtea import MODE_CBC, MODE_CTR, MODE_ECB, MODE_OFB, MODE_CFB, XTEACipher
from xtea.counter import Counter

AMOUNT = 50

if hasattr(time, "perf_counter"):
    clock = time.perf_counter
else:
    clock = time.clock


def _test_mode(mode):
    plain = os.urandom(56) * 8
    counter = Counter(os.urandom(8))
    key = os.urandom(16)
    iv = os.urandom(8)

    e = XTEACipher(key, IV=iv, counter=counter, mode=mode)
    encrypted = e.encrypt(plain)

    d = XTEACipher(key, IV=iv, counter=counter, mode=mode)

    counter.reset()
    decrypted = d.decrypt(encrypted)
    if plain != decrypted:
        raise AssertionError("Invalid decryption!")


class TestModes(unittest.TestCase):
    def testECB(self):
        print("Testing ECB")

        start = clock()
        for i in range(AMOUNT):
            _test_mode(MODE_ECB)
        end = clock()
        time = end - start
        print("Time: %s" % str(round(time, 3)))

    def testCBC(self):
        print("Testing CBC")
        start = clock()

        for i in range(AMOUNT):
            _test_mode(MODE_CBC)

        end = clock()
        time = end - start
        print("Time: %s" % str(round(time, 3)))

    def testCFB(self):
        print("Testing CFB")
        start = clock()

        for i in range(AMOUNT):
            _test_mode(MODE_CFB)

        end = clock()
        time = end - start
        print("Time: %s" % str(round(time, 3)))

    def testOFB(self):
        print("Testing OFB")
        start = clock()

        for i in range(AMOUNT):
            _test_mode(MODE_OFB)

        end = clock()
        time = end - start
        print("Time: %s" % str(round(time, 3)))

    def testCTR(self):
        print("Testing CTR")
        start = clock()

        for i in range(AMOUNT):
            _test_mode(MODE_CTR)

        end = clock()
        time = end - start
        print("Time: %s" % str(round(time, 3)))


if __name__ == "__main__":
    unittest.main()
