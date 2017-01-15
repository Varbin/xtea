################ Basic counter for CTR mode
import sys
import struct

PY_3 = sys.version_info.major >= 3

if PY_3:
    def to_bytes(integer, length, byteorder):
        return integer.to_bytes(length, byteorder)

    def from_bytes(bytesarray, byteorder):
        return int.from_bytes(bytesarray, byteorder)
else:
    def to_bytes(integer, length, byteorder='big'):
        h = '%x' % integer    
        s = ('0'*(len(h) % 2) + h).zfill(length*2).decode('hex')
        if byteorder == 'big':
            return s 
        elif byteorder =='little':
            return s[::-1]
        else:
            raise ValueError("byteorder must be either 'little' or 'big'")

    def from_bytes(bytesarray, byteorder):
        if len(bytesarray) == 4:
            size = 'L'
        elif len(bytesarray) == 8:
            size = 'Q'
            
        if byteorder=='big':
            return struct.unpack(">"+size, bytesarray)[0]
        elif byteorder=='little':
            return struct.unpack("<"+size, bytesarray)[0]
        else:
            raise ValueError("byteorder must be either 'little' or 'big'")

class Counter:
    """Small counter for CTR mode, based on arrays
    Example:
    
        >>> from xtea3 import Counter
        >>> nonce = b"$2dUI84e" # This should be random
        >>> c = Counter(nonce)
        >>> c()
        b'%2dUI84e'
        >>> c()
        b'&2dUI84e'
        >>> c()
        b"'2dUI84e"
        >>> c.reset()
        >>> c()
        b'%2dUI84e'
    """
    
    def __init__(self, nonce, byteorder='big'):
        """Constructor for a counter which is suitable for CTR mode.
        Args:
            nonce (bytes): The start value, \
            it MUST be random if it should be secure, for example, use *os.urandom* for it.
        """

        self.__nonce = nonce
        self.byteorder = byteorder
        self.reset()

    def __call__(self):
        """The method that makes it callable.
        Returns:
            bytes
        """
        
        value = to_bytes(self.__current, 8, self.byteorder)
        self.__current += 1
        return value
    
    def reset(self):
        """Reset the counter to the nonce
        """

        self.__current = from_bytes(self.__nonce, self.byteorder)
