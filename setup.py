from __future__ import with_statement  # Reading README

import warnings

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

EXCLUDE_EXTENSION_FLAG = '--exclude-extension'
TEST = any((
    "pytest" in sys.argv,
    "test" in sys.argv,
    "ptr" in sys.argv
))
DEVELOP = 'develop' in sys.argv[1:]
BUILD_EXTENSION = not any((
    platform.python_implementation() != "CPython",
    sys.version_info[0] < 3,
    (sys.platform == 'win32'
        and sys.version_info[0] == 3
        and sys.version_info[1] == 4),
    EXCLUDE_EXTENSION_FLAG in sys.argv,
    TEST,
    DEVELOP
))

if EXCLUDE_EXTENSION_FLAG in sys.argv:
    sys.argv.pop(sys.argv.index(EXCLUDE_EXTENSION_FLAG))


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
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Topic :: Security",
        "Topic :: Security :: Cryptography"
    ],
    setup_requires = [],
    tests_require = [],
    install_requires=['pep272-encryption>=0.3'],
    python_requires='>=2.7,!=3.0.*,!=3.1.*,!=3.2.*'
)

if TEST or DEVELOP:
    warnings.warn("""Using `setup.py test` or `setup.py develop` may have \
undesired side effects.

Setuptools may install missing packages directly, instead of invocing `pip`. \
It does not have a proper dependency resolver, ignores previously used \
constraints, and ignores `pip --require-hashes`.

As an alternative for `setup.py test` use the `pytest`, and instead of \
`setup.py develop` use `pip install -e .`.""")
if TEST:
    kwargs["tests_require"] += ["pytest"]
    kwargs["setup_requires"] += ["pytest_runner"]

if BUILD_EXTENSION:
    n_args = kwargs.copy()
    n_args["ext_modules"] = [
        Extension('_xtea',
                  sources=['xtea.c'],
                  optional=True,
                  py_limited_api=True)
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
