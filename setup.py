try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

with open("README.rst") as rm:
    long_text = rm.read()

setup(name='xtea',
      version='0.1.1',
      description="A python version of XTEA",
      long_description = long_text,
      author="Simon Biewald",
      author_email="simon.biewald@hotmail.de",
      py_modules=['xtea'],
      classifiers=[
	"Development Status :: 4 - Beta",
	"Operating System :: OS Independent",
	"Programming Language :: Python :: 2 :: Only",
	"Topic :: Security :: Cryptography"]
      )
