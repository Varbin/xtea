Changelog
---------

Version 0.2.1 - dev; Jul 10, 2014
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

[18w14c] Updated upload.py

[18w14b] Fixed wrong dev number (0.2.1 -> 18w14) added upload.py for uploading to github

[18w14a] Better Wheel support and changelog

 - Added better wheel support for uploading (just for me) with a setup.cfg
 - Added this file (auto uploading on pypi/warehouse and github)

Version 0.2.0; Jul 9, 2014
~~~~~~~~~~~~~~~~~~~~~~~~~~

[0.2.0] Added a test feature; warning in CTR

 - Added a test feature
 - Raises warning on CTR, added a handler that CTR will not crash anymore ;) 

Version 0.1.1; Jul 9, 2014
~~~~~~~~~~~~~~~~~~~~~~~~~~

[0.1.1] NotImplementedError on CFB

 - Module raises a NotImplementedError on CFB
 - Minor changes

Version 0.1; Jun 22, 2014
~~~~~~~~~~~~~~~~~~~~~~~~~

[0.1] Initial release

 - Supports all mode except CFB
 - Buggy CTR ( "ß" = "\xc3\x9f" )
 - Working with PEP 272, default mode is ECB