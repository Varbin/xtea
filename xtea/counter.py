"""
Simple counter for the CTR mode of operation.
"""

import struct
import sys

PY_3 = sys.version_info.major >= 3

if PY_3:

    def to_bytes(integer, length, byteorder):
        """Convert integer to bytes."""
        return integer.to_bytes(length, byteorder)

    def from_bytes(bytesarray, byteorder):
        """Get int from from bytes"""
        return int.from_bytes(bytesarray, byteorder)
else:

    def to_bytes(integer, length, byteorder='big'):
        """Convert integer to bytes."""
        hexr = '%x' % integer
        string = ('0' * (len(hexr) % 2) + hexr).zfill(length * 2).decode('hex')

        if byteorder == 'big':
            return string
        if byteorder == 'little':
            return string[::-1]

        raise ValueError("byteorder must be either 'little' or 'big'")

    def from_bytes(bytesarray, byteorder):
        """Get int from from bytes"""
        if len(bytesarray) == 4:
            size = 'L'
        elif len(bytesarray) == 8:
            size = 'Q'
        else:
            raise ValueError("Only 4 and 8 byte counters are "
                             "supported on Python 2.")

        if byteorder == 'big':
            return struct.unpack(">" + size, bytesarray)[0]
        if byteorder == 'little':
            return struct.unpack("<" + size, bytesarray)[0]

        raise ValueError("byteorder must be either 'little' or 'big'")


class Counter:
    """Small counter for CTR mode.
    Example:

        >>> from xtea.counter import Counter
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

        nonce (bytes): The start value;
                it MUST be unique to be secure.
                The secrets module or os.urandom(n) are solid
                choices for generating random bytes.
        """
        self.__nonce = nonce
        self.byteorder = byteorder
        self.__current = from_bytes(self.__nonce, self.byteorder)

    def __call__(self):
        """Increase the counter by one.

        Returns:
            bytes
        """
        value = to_bytes(self.__current, 8, self.byteorder)
        self.__current += 1
        self.__current %= 2**64
        return value

    def reset(self):
        """Reset the counter to the nonce."""

        self.__current = from_bytes(self.__nonce, self.byteorder)
