===========
Python XTEA
===========

.. image:: https://github.com/varbin/xtea/workflows/QA/badge.svg
   :target: https://github.com/Varbin/xtea/actions
   :alt: Github Actions: QA

.. image:: https://api.codeclimate.com/v1/badges/563d6ad2607d6ed6fda3/maintainability
   :target: https://codeclimate.com/github/Varbin/xtea/maintainability
   :alt: Maintainability

.. image:: https://api.codeclimate.com/v1/badges/563d6ad2607d6ed6fda3/test_coverage
   :target: https://codeclimate.com/github/Varbin/xtea/test_coverage
   :alt: Test Coverage

.. image:: https://readthedocs.org/projects/xtea/badge/?version=latest
   :target: https://xtea.readthedocs.io/en/latest/?badge=latest
   :alt: Documentation Status


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
    

Resources
=========

* PyPi: https://pypi.org/project/xtea
* Docs: http://xtea.readthedocs.io/
* Source code: https://github.com/varbin/xtea
* Issue tracker: https://github.com/varbin/xtea/issues
