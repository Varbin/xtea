################ Basic counter for CTR mode
from xtea import from_bytes, to_bytes

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
        self.__current %= 2**64
        return value
    
    def reset(self):
        """Reset the counter to the nonce
        """

        self.__current = from_bytes(self.__nonce, self.byteorder)

