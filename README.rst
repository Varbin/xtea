===========
Python XTEA
===========

.. image:: https://api.codeclimate.com/v1/badges/563d6ad2607d6ed6fda3/maintainability
   :target: https://codeclimate.com/github/Varbin/xtea/maintainability
   :alt: Maintainability

.. image:: https://api.codeclimate.com/v1/badges/563d6ad2607d6ed6fda3/test_coverage
   :target: https://codeclimate.com/github/Varbin/xtea/test_coverage
   :alt: Test Coverage

This is an XTEA-Cipher implementation in Python (eXtended Tiny Encryption Algorithm).

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
    >>> text == x.decrypt(c)
    True
    
Note
====
   
    I do NOT guarantee that this implementation (or the base cipher) is secure. If you find bugs, please report them at
    https://github.com/Varbin/xtea/issues . 

