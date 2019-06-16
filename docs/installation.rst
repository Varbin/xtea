Installation
============

The easiest way to install `xtea` is using
`pip <https://pypi.org/project/pip/>`_:

.. code-block::

   pip install xtea

On Windows, pip might not be in your path.
Instead you might use:

.. code-block::

   py -m pip install xtea

Extension module
----------------

This packages providers an extension module written in C with
an increase upto the factor of 10.
The module is entirely optional and the installation will proceed
if the compilation fails,
PyPi contains pre built wheels for recent Python
versions on Windows.

The `setup.py` script will only attempt to build the C extension
if all of the following conditions are met:

* Python major version is 3 or larger
* The Python implementation is CPython
  (the one from `python.org <https://python.org>`_
* Not using Python 3.4 on Windows, as it will not compile properly
* Not using :code:`setup.py develop` or :code:`setup.py test`

