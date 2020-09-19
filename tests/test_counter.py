"""
Test the counter component.
"""

import unittest

from xtea.counter import Counter, to_bytes, from_bytes

# pylint: disable=missing-function-docstring


class TestIntToBytes(unittest.TestCase):
    """
    Test the conversion of integers to bytes.
    """

    def test_little_endian(self):
        result = to_bytes(0x04030201, 4, 'little')
        expected = b'\x01\x02\x03\x04'
        self.assertEqual(result, expected)

    def test_big_endian(self):
        result = to_bytes(0x01020304, 4, 'big')
        expected = b'\x01\x02\x03\x04'
        self.assertEqual(result, expected)

    def test_invalid_byte_order(self):
        with self.assertRaises(ValueError):
            to_bytes(100, 4, 'banana')


class TestBytesToInt(unittest.TestCase):
    """
    Test the conversion of bytes to integers.
    """

    def test_little_endian(self):
        result = from_bytes(b'\x01\x02\x03\x04', 'little')
        expected = 0x04030201
        self.assertEqual(result, expected)

    def test_big_endian(self):
        result = from_bytes(b'\x01\x02\x03\x04', 'big')
        expected = 0x01020304
        self.assertEqual(result, expected)

    def test_invalid_byte_order(self):
        with self.assertRaises(ValueError):
            from_bytes(b'\x01\x02\x03\x04', 'banana')


class TestCounter(unittest.TestCase):
    """
    Test the actual counter class
    """

    def test_little_endian(self):
        counter = Counter(b'\x00\x00\x00\x00\x00\x00\x00\x00', 'little')
        self.assertEqual(counter(), b'\x00\x00\x00\x00\x00\x00\x00\x00')
        self.assertEqual(counter(), b'\x01\x00\x00\x00\x00\x00\x00\x00')

    def test_big_endian(self):
        counter = Counter(b'\x00\x00\x00\x00\x00\x00\x00\x00', 'big')
        self.assertEqual(counter(), b'\x00\x00\x00\x00\x00\x00\x00\x00')
        self.assertEqual(counter(), b'\x00\x00\x00\x00\x00\x00\x00\x01')

    def test_overflow(self):
        counter = Counter(b'\xff\xff\xff\xff\xff\xff\xff\xff', 'little')
        self.assertEqual(counter(), b'\xff\xff\xff\xff\xff\xff\xff\xff')
        self.assertEqual(counter(), b'\x00\x00\x00\x00\x00\x00\x00\x00')


if __name__ == "__main__":
    unittest.main()
