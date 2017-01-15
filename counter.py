################ Basic counter for CTR mmode
import array

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
    
    def __init__(self, nonce):
        """Constructor for a counter which is suitable for CTR mode.
        Args:
            nonce (bytes): The start value, \
            it MUST be random if it should be secure, for example, use *os.urandom* for it.
        """

        self.__nonce = nonce
        self.reset()

    def __call__(self):
        """The method that makes it callable.
        Returns:
            bytes
        """

        for i in range(len(self.__current)):
            try:
                self.__current[i] += 1
                break
            except:
                self.__current[i] = 0
        return self.__current.tostring()
    
    def reset(self):
        """Reset the counter to the nonce
        """

        self.__current = array.array("B", self.__nonce)
