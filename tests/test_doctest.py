import doctest
import os
import sys

import xtea
import xtea.counter


def test_init():
    if sys.version_info[0] > 2:
        doctest.testmod(xtea, raise_on_error=True)

def test_counter():
    if sys.version_info[0] > 2:
        doctest.testmod(xtea.counter, raise_on_error=True)

def test_readme():
    if sys.version_info[0] > 2:
        doctest.testfile(
            os.path.join(
                os.path.join(os.path.dirname(__file__), ".."), "README.rst"),
            raise_on_error=True
        )