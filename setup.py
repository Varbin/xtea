from __future__ import with_statement  # Reading README

try:
    from setuptools import setup, Extension
except ImportError:
    from distutils.core import setup, Extension

from distutils.errors import (
    CCompilerError,
    DistutilsExecError,
    DistutilsPlatformError
)


import re
import platform
import sys
import traceback

BUILD_EXTENSION = not any((
    platform.python_implementation() != "CPython",
    sys.version_info[0] < 3,
    (sys.platform == 'win32'
        and sys.version_info[0] == 3
        and sys.version_info[1] == 4),
    'test' in sys.argv[1:],
    'develop' in sys.argv[1:]
))


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


kwargs = dict(
    name='xtea',
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
        "Topic :: Security :: Cryptography"
    ],
    setup_requires=['pytest-runner'],
    tests_require=['pytest'],
    install_requires=['pep272-encryption>=0.3'],
)


if BUILD_EXTENSION:
    sys.stdout.write("Trying to setup extension module!\n")
    n_args = kwargs.copy()
    n_args["ext_modules"] = [
        Extension('_xtea',
                  sources=['xtea.c'],
                  optional=True)
    ]

    try:
        setup(**n_args)
    except CCompilerError:
        sys.stderr.write("Could not install extension module - "
                         "is your C compiler working correctly?\n")
    except DistutilsPlatformError:
        sys.stderr.write("Could not install extension module - "
                         "platform error?\n")
    except DistutilsExecError:
        sys.stderr.write("Could not install extension module - "
                         "is a C compiler installed?\n")
    except Exception as e:  # noqa
        sys.stderr.write("Could not install with extension module, "
                         "but this might not be the cause.\n")
        sys.stderr.write("This is the error:\n")
        traceback.print_exc()
    else:
        sys.exit(0)

setup(**kwargs)
