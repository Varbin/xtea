from __future__ import with_statement  # Reading README

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

import re


def get_file(name):
    try:
        with open(name) as f:
            return f.read()
    except IOError:  # OSError on Py3
        return ''


META_FILE = get_file("xtea/__init__.py")


def find_meta(meta):
    """
    Extract __*meta*__ from META_FILE.

    Source: https://github.com/python-attrs/attrs/blob/master/setup.py#L73
    """
    meta_match = re.search(
        r"^__{meta}__ = ['\"]([^'\"]*)['\"]".format(meta=meta), META_FILE, re.M
    )
    if meta_match:
        return meta_match.group(1)

    raise RuntimeError("Unable to find __{meta}__ string.".format(meta=meta))


long_text = get_file("README.rst") + "\n\n" + get_file("changelog.rst")

setup(name='xtea',
      version=find_meta("version"),
      description="A python version of XTEA",
      long_description=long_text,
      author=find_meta("author"),
      author_email=find_meta("email"),
      url="https://github.com/Varbin/xtea/wiki",
      download_url="https://github.com/Varbin/xtea",
      bugtrack_url="https://github.com/Varbin/xtea/issues",
      keywords="xtea tea encryption cryptography",
      license=find_meta("license"),
      packages=["xtea"],
      classifiers=[
        "Development Status :: 4 - Beta",
        "License :: Public Domain",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Topic :: Security",
        "Topic :: Security :: Cryptography"],
      setup_requires=['pytest-runner'],
      tests_require=['pytest'],
      install_requires=['pep272-encryption'],
      )
