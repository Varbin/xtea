"""
XTEA-Cipher in Python (eXtended Tiny Encryption Algorithm)

XTEA is a blockcipher with 8 bytes blocksize and 16 bytes Keysize (128-Bit).
The algorithm is secure at 2014 with the recommend 64 rounds (32 cycles). This
implementation supports following modes of operation:
ECB, CBC, OFB, CTR

Example:

>>> from xtea import *
>>> key = " "*16  # Never use this
>>> text = "This is a text. "*8
>>> x = new(key, mode=MODE_OFB, IV="12345678")
>>> c = x.encrypt(text)
>>> c.encode("hex")
'fa66ec11b82e38bc77c14be093bb8aa0d7fe0fb9e6ec015
7a22d254fee43aea9a64c8dbb2c2b899f66800f264419c8e
8796ad8f94c7758b916428019d10573943324a9dcf60f883
1f0f925cd7215e5dd4f1334d9ee242d41ac02d0a64c49663
e5897bfd2450982379267e6cd7405b477ccc19d6c0d32e2f
887b76fe01d621a8d'
>>> text == x.decrypt(c)
True
"""


import struct
import binascii

MODE_ECB = 1
MODE_CBC = 2
MODE_CFB = 3
MODE_OFB = 5
MODE_CTR = 6


block_size = 64
key_size = 128


def new(key, **kwargs):
    """Create an cipher object.

    Keyword arguments
    key -- the key for encrypting (and decrypting)

    Other arguments:
    mode -- Block cipher mode of operation (default MODE_ECB)
    IV -- Initialisation vector (needed with CBC/CFB)
    counter -- a callable counter (needed with CTR)
    endian -- how to use struct (default "!" (big endian/network))    """
    return XTEACipher(key, **kwargs)


class XTEACipher(object):
    """The cipher class

    Functions:
    encrypt -- encrypt data
    decrypt -- decrypt data

    _block -- splits the data in blocks (you may need padding)

    Constants:
    bloc_size = 8

    Variables:
    IV -- the initialisation vector (default None or "\00"*8)
    conuter -- counter for CTR (default None)
    
    """
    
    block_size = 8
    IV = None
    counter = None
    
    def __init__(self, key, **kwargs):
        """Initiate the cipher
        same arguments as for new."""
        self.key = key
        if len(key) != key_size/8:
            raise ValueError("Key must be 128 bit long")
        keys = kwargs.keys()
        if "mode" in keys:
            self.mode = kwargs["mode"]
        else:
            self.mode = MODE_ECB
        if "IV" in keys:
            self.IV = kwargs["IV"]
            if len(self.IV) != self.block_size:
                raise ValueError("IV must be 8 bytes long")
        elif self.mode == MODE_CBC or self.mode == MODE_CFB:
            raise ValueError("CBC, CFB need an IV")
        elif self.mode == MODE_OFB:
            self.IV = '\00\00\00\00\00\00\00\00'
        if "counter" in keys:
            self.counter = kwargs["counter"]
        elif self.mode == MODE_CTR:
            raise ValueError("CTR needs a counter")
        if "rounds" in keys:
            self.rounds = kwargs["rounds"]
        else:
            self.rounds = 64
        if "endian" in keys:
            self.endian = kwargs["endian"]
        else:
            self.endian = "!"

    def encrypt(self, data):
        """Encrypt data.

        Keyword arguments:
        data -- the data (plaintext) to encrypt

        On OFB, encrypt and decrypt is the same.
        """

        #ECB
        if self.mode == MODE_ECB:
            if not len(data) % (self.block_size/8):
                out = []
                blocks=self._block(data)
                for block in blocks:
                    out.append(_encrypt(self.key, block, self.rounds/2, self.endian))
                return "".join(out)
            else:
                raise ValueError("Input string must be a multiple of blocksize in length")

        #CBC
        elif self.mode == MODE_CBC:
            if not len(data) % (self.block_size/8):
                out = [self.IV]
                blocks=self._block(data)
                for i in range(0, len(blocks)):
                    xored = xor_strings(blocks[i], out[i])
                    out.append(_encrypt(self.key,xored,self.rounds/2,self.endian))
                return "".join(out[1:])
            else:
                raise ValueError("Input string must be a multiple of blocksize in length")
        #OFB
        elif self.mode == MODE_OFB:
            return _crypt_ofb(self.key, data, self.IV, self.rounds/2)

        #CFB

        #CTR
        elif self.mode == MODE_CTR:
            blocks = self._block(data)
            out = []
            for block in blocks:
                c = self.counter()
                n = stringToLong(block)
                out.append(_encrypt(self.key,struct.pack(self.endian+'Q', n^c), self.rounds/2, self.endian))
            return "".join(out)

    def decrypt(self, data):
        """Decrypt data.

        Keyword arguments:
        data -- the data (ciphertext) to decrypt.

        On OFB, encrypt and decrypt is the same.
        """
        #ECB
        if self.mode == MODE_ECB:
            if not len(data) % (self.block_size/8):
                out = []
                blocks=self._block(data)
                for block in blocks:
                    out.append(_decrypt(self.key, block, self.rounds/2, self.endian))
                return "".join(out)
            else:
                raise ValueError("Input string must be a multiple of blocksize in length")

        #CBC
        elif self.mode == MODE_CBC:
            out = []
            blocks = self._block(data)
            blocks = [self.IV]+blocks
            for i in range(1, len(blocks)):
                out.append(xor_strings(_decrypt(self.key,blocks[i],self.rounds/2,self.endian), blocks[i-1]))
            return "".join(out)
        #OFB
        elif self.mode == MODE_OFB:
            return _crypt_ofb(self.key, data, self.IV, self.rounds/2)

        #CFB

        #CTR
        elif self.mode == MODE_CTR:
            blocks = self._block(data)
            out = []
            for block in blocks:
                nc = struct.unpack(self.endian+"Q",_decrypt(self.key, block, self.rounds/2, self.endian))
                out.append(longToString(nc[0]^self.counter()))
            return "".join(out)

    def _block(self, s):
        l = []
        rest_size = len(s) % self.block_size
        for i in range(len(s)/self.block_size):
            l.append(s[i*self.block_size:((i+1)*self.block_size)])
        if rest_size:
            raise ValueError()
        return l



################ Util functions: basic encrypt/decrypt, OFB, xor, stringToLong
"""
This a utilities only, use them only if you know what you do.

Functions:
_crypt_ofb -- Encrypt or decrypt data in OFB mode.
_encrypt -- Encrypt one single block of data.
_decrypt -- Decrypt one single block of data.
xor_strings -- xor to strings together.
stringToLong -- Convert any string to a number.
longToString --Convert some longs to string.
"""

def _crypt_ofb(key,data,iv='\00\00\00\00\00\00\00\00',n=32):
    """Encrypt or decrypt data in OFB mode.

    Only use if you know what you do.

    Keyword arguments:
    key -- the key for encrypting (and decrypting)
    data -- plain / ciphertext
    iv -- initialisation vector (default "\x00"*8)
    n -- cycles, more cycles -> more security (default 32)
    """
    def keygen(key,iv,n):
        while True:
            iv = _encrypt(key,iv,n)
            for k in iv:
                yield ord(k)
    xor = [ chr(x^y) for (x,y) in zip(map(ord,data),keygen(key,iv,n)) ]
    return "".join(xor)

def _encrypt(key,block,n=32,endian="!"):
    """Encrypt one single block of data.

    Only use if you know what to do.

    Keyword arguments:
    key -- the key for encrypting (and decrypting)
    block  -- one block plaintext
    n -- cycles, one cycle is two rounds, more cycles
          -> more security and slowness (default 32)
    endian -- how struct will handle data (default "!" (big endian/network))
    """
    v0,v1 = struct.unpack(endian+"2L",block)
    k = struct.unpack(endian+"4L",key)
    sum,delta,mask = 0L,0x9e3779b9L,0xffffffffL
    for round in range(n):
        v0 = (v0 + (((v1<<4 ^ v1>>5) + v1) ^ (sum + k[sum & 3]))) & mask
        sum = (sum + delta) & mask
        v1 = (v1 + (((v0<<4 ^ v0>>5) + v0) ^ (sum + k[sum>>11 & 3]))) & mask
    return struct.pack(endian+"2L",v0,v1)

def _decrypt(key,block,n=32,endian="!"):
    """Decrypt one single block of data.

    Only use if you know what to do.

    Keyword arguments:
    key -- the key for encrypting (and decrypting)
    block  -- one block ciphertext
    n -- cycles, one cycle is two rounds, more cycles
          -> more security and slowness (default 32)
    endian -- how struct will handle data (default "!" (big endian/network))
    """
    v0,v1 = struct.unpack(endian+"2L",block)
    k = struct.unpack(endian+"4L",key)
    delta,mask = 0x9e3779b9L,0xffffffffL
    sum = (delta * n) & mask
    for round in range(n):
        v1 = (v1 - (((v0<<4 ^ v0>>5) + v0) ^ (sum + k[sum>>11 & 3]))) & mask
        sum = (sum - delta) & mask
        v0 = (v0 - (((v1<<4 ^ v1>>5) + v1) ^ (sum + k[sum & 3]))) & mask
    return struct.pack(endian+"2L",v0,v1)

def xor_strings(s,t):
    """xor to strings together.

    Keyword arguments:
    s -- string one
    t -- string two
    """
    return "".join(chr(ord(a)^ord(b)) for a,b in zip(s,t))


def stringToLong(s):
    """Convert any string to a number."""
    return long(binascii.hexlify(s),16)

def longToString(n):
    """Convert some longs to string."""
    return binascii.unhexlify("%x" % n)
