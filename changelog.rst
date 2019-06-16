Changelog
---------

Version 0.7.1, former 0.6.1 / 0.7.0; Jun 16, 2018
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- Improved tests
- PEP8-style formatting
- Unittests: Counter, modes (but not results of them!), test vectors
- [BREAKING CHANGE] Counter class is now in xtea.counter
- Python 3.3 is not tested anymore on Travis CI
- [BREAKING CHANGE] CFB mode is now correctly implemented.
  By setting ``partition_size`` it is possible to set the
  internal partition size (in bits) as per PEP-272.
- Python 3: An optional C extension improves speed upto a factor of 10.
- [BREAKING CHANGE] `block_size` and `key_size` is now in bytes.
- Skipped 0.7.0 with

(unreleased) Version 0.6.0; Oct 16, 2016
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- Python 3 does work now
- [BREAKING CHANGE] counters cannot return numbers any more, they must return bytestrings now
- [BREAKING CHANGE] Cipher objects remember state, so two consecutive calls to XTEACipher.encrypt should not return the same
- improved documentation

(unreleased) Version 0.5.0; Oct 15, 2016
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- Removed CBCMAC

Version 0.4.1; Jul 30, 2015
~~~~~~~~~~~~~~~~~~~~~~~~~~~

- Fixed installer

Version 0.4.0; Jul 12, 2014
~~~~~~~~~~~~~~~~~~~~~~~~~~~

- Buggless & PEP compliant CTR
- CTR mode works with strings now
- raises DeprecatedWarning if a number is returned
- CBCMAC class added (use static method CBCMAC.new(args) to create)

Version 0.3.2; Jul 11, 2014
~~~~~~~~~~~~~~~~~~~~~~~~~~~

- Minor Fixes

Version 0.3.1; Jul 11, 2014
~~~~~~~~~~~~~~~~~~~~~~~~~~~

- Minor Fixes
- Fixed that the length of data will not be checked

Version 0.3.0; Jul 11, 2014
~~~~~~~~~~~~~~~~~~~~~~~~~~~

- Added CFB mode
- Fully working with PEP 272
- Raising NotImplementedError only on PGP-CFB (OpenPGP) mode
- Wheel support and changelog (0.2.1)

(unreleased) Version 0.2.1 - dev; Jul 10, 2014
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- Added better wheel support for uploading (just for me) with a setup.cfg
- Added this file (auto uploading on pypi/warehouse and github)
- (upload.py for github)

Version 0.2.0; Jul 9, 2014
~~~~~~~~~~~~~~~~~~~~~~~~~~

- Added a test feature; warning in CTR
- Raises warning on CTR, added a handler that CTR will not crash anymore ;)

Version 0.1.1; Jul 9, 2014
~~~~~~~~~~~~~~~~~~~~~~~~~~

- Module raises a NotImplementedError on CFB
- Minor changes

Version 0.1; Jun 22, 2014
~~~~~~~~~~~~~~~~~~~~~~~~~

- Initial release
- Supports all mode except CFB
- Buggy CTR ( "ß" = "\\xc3\\x9f" )
- Working with PEP 272, default mode is ECB
