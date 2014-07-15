"""
XTEA-Cipher in Python (eXtended Tiny Encryption Algorithm)

XTEA is a blockcipher with 8 bytes blocksize and 16 bytes Keysize (128-Bit).
The algorithm is secure at 2014 with the recommend 64 rounds (32 cycles). This
implementation supports following modes of operation:
ECB, CBC, CFB, OFB, CTR

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
import sys
import warnings
import types

MODE_ECB = 1
MODE_CBC = 2
MODE_CFB = 3
MODE_PGP = 4
MODE_OFB = 5
MODE_CTR = 6

MODE_CCM = 8 # Unofficial


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

################ XTEACipher class

class XTEACipher(object):
    """The cipher class

    Functions:
    encrypt -- encrypt data
    decrypt -- decrypt data

    _block -- splits the data in blocks (you may need padding)

    Constants:
    block_size = 8

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
        if len(key) != key_size/8: # Check key len
            raise ValueError("Key must be 128 bit long")
        keys = kwargs.keys() # arguments
        if "mode" in keys: # check for mode
            self.mode = kwargs["mode"] # read mode
        else:
            self.mode = MODE_ECB # if not given
        if self.mode == MODE_PGP: 
            raise NotImplementedError("PGP-CFB is not implemented")
        if "IV" in keys: # get iv
            self.IV = kwargs["IV"]
            if len(self.IV) != self.block_size: # iv len = blocksize
                raise ValueError("IV must be 8 bytes long")
        elif self.mode == MODE_CBC or self.mode == MODE_CFB: # cfb & cbc need iv
            raise ValueError("CBC, CFB need an IV")
        elif self.mode == MODE_OFB: # ofb nocne if not given = "\x00" * 16
            self.IV = '\00\00\00\00\00\00\00\00'
        if "counter" in keys: # ctr needs counter
            self.counter = kwargs["counter"]
        elif self.mode == MODE_CTR: # if ctr and counter not given
            raise ValueError("CTR needs a counter")
        if "rounds" in keys: # rounds to operate
            self.rounds = kwargs["rounds"]
        else:
            self.rounds = 64
        if "endian" in keys: # endian for struct str -> int -> str (byte order)
            self.endian = kwargs["endian"]
        else:
            self.endian = "!" # default network/big endian

    def encrypt(self, data):
        """Encrypt data.

        Keyword arguments:
        data -- the data (plaintext) to encrypt

        On OFB, encrypt and decrypt is the same.
        """

        #ECB
        if self.mode == MODE_ECB:
            if not len(data) % (self.block_size):
                out = []
                blocks=self._block(data)
                for block in blocks:
                    out.append(_encrypt(self.key, block, self.rounds/2, self.endian))
                return "".join(out)
            else:
                raise ValueError("Input string must be a multiple of blocksize in length")

        #CBC
        elif self.mode == MODE_CBC:
            if not len(data) % (self.block_size):
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
        elif self.mode == MODE_CFB:
            if not len(data) % self.block_size:
                blocks = self._block(data)
                out = []
                fb = self.IV
                for bn in blocks:
                    tx = _encrypt(self.key, fb, self.rounds/2, self.endian)
                    fb = xor_strings(bn, tx)
                    out.append(fb)
                return "".join(out)
            else:
                raise ValueError("Input string must be a multiple of blocksize in length")

        #CTR
        elif self.mode == MODE_CTR:
            l = (types.IntType, types.LongType, types.FloatType) # Typelist
            
            blocks = self._block(data)
            out = []
            for block in blocks:
                c = self.counter()
                if type(c) in l:
                    warnings.warn(
                        "Numbers as counter-value is buggy and deprecated!",
                        DeprecationWarning)
                    n = stringToLong(block)
                    out.append(
                        _encrypt(
                            self.key,struct.pack(self.endian+'Q', n^c),
                            self.rounds/2, self.endian))
                else:
                    n = block
                    out.append(
                        _encrypt(
                            self.key,
                            xor_strings(n, c),
                            self.rounds/2,
                            self.endian)
                        )
            return "".join(out)

    def decrypt(self, data):
        """Decrypt data.

        Keyword arguments:
        data -- the data (ciphertext) to decrypt.

        On OFB, encrypt and decrypt is the same.
        """
        #ECB
        if self.mode == MODE_ECB:
            if not (len(data) % self.block_size):
                out = []
                blocks=self._block(data)
                for block in blocks:
                    out.append(_decrypt(self.key, block, self.rounds/2, self.endian))
                return "".join(out)
            else:
                raise ValueError("Input string must be a multiple of blocksize in length")

        #CBC
        elif self.mode == MODE_CBC:
            if not (len(data) % self.block_size):
                out = []
                blocks = self._block(data)
                blocks = [self.IV]+blocks
                for i in range(1, len(blocks)):
                    out.append(
                        xor_strings(
                            _decrypt(
                                self.key,blocks[i]
                                ,self.rounds/2,
                                self.endian),
                            blocks[i-1])
                        )
                return "".join(out)
        #OFB
        elif self.mode == MODE_OFB:
            return _crypt_ofb(self.key, data, self.IV, self.rounds/2)

        #CFB
        elif self.mode == MODE_CFB:
            if not len(data) % self.block_size:
                blocks = self._block(data)
                out = []
                fb = self.IV
                for block in blocks:
                    tx = _encrypt(self.key, fb, self.rounds/2, self.endian)
                    fb = block[:]
                    out.append(xor_strings(block,tx))
                return "".join(out)
            else:
                raise ValueError("Input string must be a multiple of blocksize in length")

        #CTR
        elif self.mode == MODE_CTR:
            l = (types.IntType, types.LongType, types.FloatType)
            blocks = self._block(data)
            out = []
            for block in blocks:
                c = self.counter()
                if type(c) in l:
                    warnings.warn(
                        "Numbers as counter-value are buggy and deprecated!",
                        DeprecationWarning)
                    nc = struct.unpack(self.endian+"Q",_decrypt(self.key, block, self.rounds/2, self.endian))
                    try:
                        out.append(longToString(nc[0]^c))
                    except:
                        warnings.warn(
                            "Unable to decrypt this block, block is lost",
                            RuntimeWarning)
                        out.append("\00"*8)
                else:
                    nc = _decrypt(self.key, block, self.rounds/2, self.endian)
                    out.append(xor_strings(nc, c))
            return "".join(out)

    def _block(self, s):
        l = []
        rest_size = len(s) % self.block_size
        for i in range(len(s)/self.block_size):
            l.append(s[i*self.block_size:((i+1)*self.block_size)])
        if rest_size:
            raise ValueError()
        return l

################ CBCMAC class

class CBCMAC(object):
    name = "xtea-cbcmac"
    block_size = 64
    digest_size = 8
    
    """Just a small implementation of the CBCMAC algorithm, based on XTEA."""
    def __init__(self, key, string="", endian="!"):
        warnings.warn("This is experimental!")
        self.cipher = new(key, mode=MODE_CBC, IV="\00"*8, endian=endian)
        self.text = string
        self.key = key

    @staticmethod
    def new(key, string="", endian="!"):
        return CBCMAC(key, string, endian)

    def update(self, string):
        self.text += string

    def copy(self):
        return CBCMAC.new(self.key, self.text, self.cipher.endian)

    def digest(self):
        return self.cipher.encrypt(self.text)[-8:]

    def hexdigest(self):
        return binascii.hexlify(self.digest())

################ Util functions: basic encrypt/decrypt, OFB, xor, stringToLong
"""
This are utilities only, use them only if you know what you do.

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
    n -- cycles, one cycle is two rounds, more cycles =
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

c = 0  # Test (double global)

def _test():
    global c
    import os
    from time import clock
    print "Starting test..."
    print "Testing ECB"
    fails_ecb = 0
    start = clock()
    for i in range(250):
        try:
            plain = os.urandom(56)*8
            e = new(os.urandom(16))
            encrypted = e.encrypt(plain)
            decrypted = e.decrypt(encrypted)
            if decrypted != plain: fails_ecb += 1
        except:
            print >> sys.stderr, "Fail with Error..."
            fails_ecb+=1
    end = clock()
    time_ecb = end - start

    print "Testing CBC"
    fails_cbc = 0
    start = clock()
    for i in range(250):
        try:
            key = os.urandom(16)
            iv = os.urandom(8)
            c1 = new(key, mode=MODE_CBC, IV=iv)
            c2 = new(key, mode=MODE_CBC, IV=iv)
            plain = os.urandom(56)*8
            encrypted = c1.encrypt(plain)
            decrypted = c2.decrypt(encrypted)
            if decrypted != plain: fails_cbc+=1
            
        except:
            print >> sys.stderr, "Fail with Error..."
            fails_cbc+=1
    end = clock()
    time_cbc = end - start

    print "Testing CFB"
    fails_cfb = 0
    start = clock()
    for i in range(250):
        try:
            key = os.urandom(16)
            iv = os.urandom(8)
            c1 = new(key, mode=MODE_CFB, IV=iv)
            c2 = new(key, mode=MODE_CFB, IV=iv)
            plain = os.urandom(56)*8
            encrypted = c1.encrypt(plain)
            decrypted = c2.decrypt(encrypted)
            if decrypted != plain: fails_cfb+=1
            
        except:
            print >> sys.stderr, "Fail with Error..."
            fails_cfb+=1
    end = clock()
    time_cfb = end - start
            
    print "Testing OFB (function)"
    fails_ofb = 0
    start = clock()
    for i in range(250):
        try:
            key = os.urandom(16)
            plain = os.urandom(56)*8
            encrypted = _crypt_ofb(key, plain)
            decrypted = _crypt_ofb(key, encrypted)
            if decrypted != plain:
                fails_ofb+=1
        except:
            print >> sys.stderr, "Fail with Error..."
            fails_ofb+=1
    end = clock()
    time_ofb = end - start
    
    print "Testing CTR (old number-counter)"
    fails_ctr = 0
    def count():
        global c
        c += 1
        return c
    start = clock()
    for i in range(250):
        try:
            key = os.urandom(16)
            c_b = stringToLong(os.urandom(6))
            c=c_b
            cf = new(key, mode=MODE_CTR, counter=count)
            plain = os.urandom(56)*8
            encrypted = cf.encrypt(plain)
            c=c_b
            decrypted = cf.decrypt(encrypted)
            if decrypted != plain:
                fails_ctr+=1
        except Warning:
            pass
        except DeprecationWarning:
            print "Outdated test function..."
        except Exception:
            print >> sys.stderr, "Fail with Error..."
            fails_ctr += 1
    end = clock()
    time_ctr = end - start

    print
    print
    print "Result"
    print "="*15
    print
    print
    print "Fails:"
    print
    print "|ECB|CBC|CFB|OFB|CTR|"
    print "|---|---|---|---|---|"
    print "|%s|%s|%s|%s|%s|" % (
        str(fails_ecb).rjust(3,"0"),
        str(fails_cbc).rjust(3,"0"),
        str(fails_cfb).rjust(3,"0"),
        str(fails_ofb).rjust(3,"0"),
        str(fails_ctr).rjust(3,"0"))
    print
    print "Time:"
    print
    print "ECB: %s\nCBC: %s\nCFB: %s\nOFB: %s\nCTR: %s\n" % (
        str(time_ecb),
        str(time_cbc),
        str(time_cfb),
        str(time_ofb),
        str(time_ctr))

if __name__ == "__main__":
    _test()
