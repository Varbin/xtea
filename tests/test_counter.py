import unittest

from xtea.counter import Counter, to_bytes, from_bytes

class TestIntToBytes(unittest.TestCase):

    def testLittleEndian(self):
        result = to_bytes(67305985, 4, 'little')
        expected = b'\x01\x02\x03\x04'
        self.assertEqual(result, expected)
            
    def testBigEndian(self):
        result = to_bytes(16909060, 4, 'big')
        expected = b'\x01\x02\x03\x04'
        self.assertEqual(result, expected)
    
    def testStrangeByteOrder(self):
        with self.assertRaises(ValueError):
            to_bytes(100, 4, 'banana')

class TestBytesToInt(unittest.TestCase):

    def testLittleEndian(self):
        result = from_bytes(b'\x01\x02\x03\x04', 'little')
        expected = 67305985
        self.assertEqual(result, expected)
    
    def testBigEndian(self):
        result = from_bytes(b'\x01\x02\x03\x04', 'big')
        expected = 16909060
        self.assertEqual(result, expected)
    
    def testStrangeByteOrder(self):
        with self.assertRaises(ValueError):
            from_bytes(b'\x01\x02\x03\x04', 'banana')
    
class TestCounter(unittest.TestCase):
    
    def testLittleEndian(self):
        counter = Counter(b'\x00\x00\x00\x00\x00\x00\x00\x00', 'little')
        self.assertEqual(counter(), b'\x00\x00\x00\x00\x00\x00\x00\x00')
        self.assertEqual(counter(), b'\x01\x00\x00\x00\x00\x00\x00\x00')
    
    def testBigEndian(self):
        counter = Counter(b'\x00\x00\x00\x00\x00\x00\x00\x00', 'big')
        self.assertEqual(counter(), b'\x00\x00\x00\x00\x00\x00\x00\x00')
        self.assertEqual(counter(), b'\x00\x00\x00\x00\x00\x00\x00\x01')
        
    def testMaxValue(self):
        counter = Counter(b'\xff\xff\xff\xff\xff\xff\xff\xff', 'little')
        self.assertEqual(counter(), b'\xff\xff\xff\xff\xff\xff\xff\xff')
        self.assertEqual(counter(), b'\x00\x00\x00\x00\x00\x00\x00\x00')

