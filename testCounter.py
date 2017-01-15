import unittest

from counter import Counter, to_bytes, from_bytes

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
        pass
    
    def testBigEndian(self):
        pass

