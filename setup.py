try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

with open("README.rst") as rm:
    long_text = rm.read()

setup(name='xtea',
      version='0.2.0',
      description="A python version of XTEA",
      long_description = long_text,
      author="Simon Biewald",
      author_email="simon.biewald@hotmail.de",
      url="https://github.com/Varbin/xtea",
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
