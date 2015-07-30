from __future__ import with_statement  # Reading README
import sys
import warnings

if sys.hexversion >=0x03000000:
    warnings.warn( # Py3 for uploading
        "This module will not work with python 3+")

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

def get_file(name):
    try:
        with open(name) as f:
            return f.read()
    except:
        return ''

long_text = get_file("README.rst") + "\n\n" + get_file("changelog.rst")

setup(name='xtea',
      version='0.4.1',
      description="A python version of XTEA",
      long_description = long_text,
      author="Simon Biewald",
      author_email="simon.biewald@hotmail.de",
      url="https://github.com/Varbin/xtea/wiki",
      download_url="https://github.com/Varbin/xtea",
      bugtrack_url="https://github.com/Varbin/xtea/issues",
      keywords = "xtea tea encryption crypt", 
      license="Public Domain",
      py_modules=['xtea'],
      classifiers=[
	"Development Status :: 4 - Beta",
        "License :: Public Domain",
	"Operating System :: OS Independent",
	"Programming Language :: Python :: 2 :: Only",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: IronPython",
        "Programming Language :: Python :: Implementation :: Jython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Topic :: Security",
	"Topic :: Security :: Cryptography"]
      )
