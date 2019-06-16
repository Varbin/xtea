"""
XTEA-Cipher in Python (eXtended Tiny Encryption Algorithm)

XTEA is a blockcipher with 8 bytes blocksize and 16 bytes Keysize (128-Bit).
The algorithm is secure at 2014 with the recommend 64 rounds (32 cycles). This
implementation supports following modes of operation:
ECB, CBC, CFB, OFB, CTR

Example:

>>> from xtea import *
>>> from binascii import hexlify
>>> key = b" "*16  # Never use this
>>> text = b"This is a text. "*8
>>> x = new(key, mode=MODE_OFB, IV=b"12345678")
>>> c = x.encrypt(text)
>>> hexlify(c).decode()
'fa66ec11b82e38bc77c14be093bb8aa0d7fe0fb9e6ec015
7a22d254fee43aea9a64c8dbb2c2b899f66800f264419c8e
8796ad8f94c7758b916428019d10573943324a9dcf60f883
1f0f925cd7215e5dd4f1334d9ee242d41ac02d0a64c49663
e5897bfd2450982379267e6cd7405b477ccc19d6c0d32e2f
887b76fe01d621a8d'
>>> text == x.decrypt(c)
True
"""

from __future__ import print_function

__all__ = ("new", "XTEACipher")

__version__ = "0.7.0.dev0"
__author__ = "Simon Biewald"
__email__ = "simon@fam-biewald.de"
__license__ = "Public Domain"

import struct
import sys
import warnings

from pep272_encryption import PEP272Cipher
from .counter import Counter  # noqa: F401

try:
    from _xtea import \
        encrypt_int as _encrypt_int, \
        decrypt_int as _decrypt_int

except ImportError:
    def _encrypt_int(k, v, n=32):
        v0, v1 = v

        sum, delta, mask = 0, 0x9e3779b9, 0xffffffff
        for round in range(n):
            v0 = (v0 + (((v1 << 4 ^ v1 >> 5) + v1) ^
                        (sum + k[sum & 3]))) & mask
            sum = (sum + delta) & mask
            v1 = (v1 + (((v0 << 4 ^ v0 >> 5) + v0) ^
                        (sum + k[sum >> 11 & 3]))) & mask

        return v0, v1

    def _decrypt_int(k, v, n=32):
        v0, v1 = v

        delta, mask = 0x9e3779b9, 0xffffffff
        sum = (delta * n) & mask
        for round in range(n):
            v1 = (v1 - (((v0 << 4 ^ v0 >> 5) + v0) ^
                        (sum + k[sum >> 11 & 3]))) & mask
            sum = (sum - delta) & mask
            v0 = (v0 - (((v1 << 4 ^ v1 >> 5) + v1) ^
                        (sum + k[sum & 3]))) & mask

        return v0, v1


MODE_ECB = 1
MODE_CBC = 2
MODE_CFB = 3
MODE_PGP = 4
MODE_OFB = 5
MODE_CTR = 6

PY_3 = sys.version_info.major >= 3

if PY_3:

    def b_ord(n):
        return n

    def b_chr(n):
        return bytes([n])
else:

    def b_ord(n):
        return ord(n)

    def b_chr(n):
        return chr(n)


block_size = 64
key_size = 128


def new(key, **kwargs):
    return XTEACipher(key, **kwargs)


# XTEACipher class


class XTEACipher(PEP272Cipher):
    """The cipher class

    Functions:
    encrypt -- encrypt data
    decrypt -- decrypt data

    _block -- splits the data in blocks (you may need padding)

    Constants:
    block_size = 8

    Variables:
    IV -- the initialisation vector (default None or "\00"*8)
    counter -- counter for CTR (default None)

    """

    block_size = 8
    IV = None
    counter = None

    def __init__(self, key, mode=None, **kwargs):
        r"""
        Create an "XTEACipher" object.

        It's fully PEP-272 compliant, default mode is ECB.

        :param key:
            The key for encryption/decryption. Must be 16 in length.
        :type key: `bytes`

        :param mode:
            Mode of operation, must be one of this::

                1 = ECB
                2 = CBC
                3 = CFB
                5 = OFB
                6 = CTR

        :type mode: `int`

        :param \**kwargs:
            See below

        :Keyword arguments:
            * *IV* or *iv* (`bytes`):
                Initialization vector with 8 bytes in length.
                For **security reasons** it should be *unpredictable*
                and *must never be used twice for the same key*!.

                **Required for**: *CBC*, *CFB* and *OFB* mode of operation.


            * *counter* (``callable``):
                Callable counter which returns 8 bytes each call.
                For **security reasons** the counter must not have the same
                output twice.

                **Required for**: *CTR* mode of operation.

                .. versionchanged:: 0.5.0
                    Integers instead of callable objects are not accepted
                    anymore.

            * *segment_size* (`int`):
                The segment size for one encryption "segment" in
                *CFB* mode in *bits*. It must be a multiple of 8
                and between 8 and 64.

                **Required for**: *CFB* mode.

            * *endian* (``str``): Endianess of internal conversions.
                Defaults to "!" meaning big endian.

                 ..seealso:: modules :py:mod:`struct`

            * *rounds* (`int` or `float`):
                Rounds of the xtea cipher, defaults to 64.
        """

        if mode is None:
            mode = MODE_ECB
            warnings.warn("Implicitly selecting ECB mode of operation. "
                          "The ECB mode is usually insecure to use.")

        super(XTEACipher, self).__init__(key, mode, **kwargs)

        self.rounds = int(kwargs.get("rounds", 64))
        self.cycles = self.rounds // 2
        self.endian = kwargs.get("endian", "!")

        self.__k = struct.unpack(self.endian + "4L", self.key)

    def encrypt_block(self, key, block, **kwargs):
        encrypted_block = _encrypt_int(
            self.__k,
            struct.unpack(self.endian + "2L", block),
            self.cycles
        )

        return struct.pack(
            self.endian + "2L",
            *encrypted_block
        )

    def decrypt_block(self, key, block, **kwargs):
        decrypted_block = _decrypt_int(
            self.__k,
            struct.unpack(self.endian + "2L", block),
            self.cycles
        )

        return struct.pack(
            self.endian + "2L",
            *decrypted_block
        )


new.__doc__ = XTEACipher.__init__.__doc__

# Util functions: basic encrypt/decrypt, xor
"""
This are utilities only, use them only if you know what you do.

Functions:
_encrypt -- Encrypt one single block of data.
_decrypt -- Decrypt one single block of data.
xor_strings -- xor to strings together.
"""


def _encrypt(key, block, n=32, endian="!"):
    """Encrypt one single block of data.

    Only use if you know what to do.

    Keyword arguments:
    key -- the key for encrypting (and decrypting)
    block  -- one block plaintext
    n -- cycles, one cycle is two rounds, more cycles
          -> more security and slowness (default 32)
    endian -- how struct will handle data (default "!" (big endian/network))
    """
    v = struct.unpack(endian + "2L", block)
    k = struct.unpack(endian + "4L", key)

    v_encrypted = _encrypt_int(k, v, n)

    return struct.pack(endian + "2L", *v_encrypted)


def _decrypt(key, block, n=32, endian="!"):
    """Decrypt one single block of data.

    Only use if you know what to do.

    Keyword arguments:
    key -- the key for encrypting (and decrypting)
    block  -- one block ciphertext
    n -- cycles, one cycle is two rounds, more cycles =
          -> more security and slowness (default 32)
    endian -- how struct will handle data (default "!" (big endian/network))
    """
    v = struct.unpack(endian + "2L", block)
    k = struct.unpack(endian + "4L", key)

    v_decrypted = _decrypt_int(k, v, n)

    return struct.pack(endian + "2L", *v_decrypted)


if PY_3:

    def xor_strings(s, t):
        """xor to strings together.

        Keyword arguments:
        s -- string one
        t -- string two
        """
        return bytes([(x ^ y) for x, y in zip(s, t)])
else:

    def xor_strings(s, t):
        """xor to strings together.

        Keyword arguments:
        s -- string one
        t -- string two
        """
        return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(s, t))
