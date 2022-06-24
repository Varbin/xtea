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
