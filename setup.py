#!/usr/bin/python
from setuptools import setup

setup(name='rfc3161',
      version='1.0.7',
      license='MIT',
      url='https://dev.entrouvert.org/projects/python-rfc3161',
      description='Python implementation of the RFC3161 specification, using pyasn1',
      long_description=file('README').read(),
      author='Benjamin Dauvergne',
      author_email='bdauvergne@entrouvert.com',
      packages=['rfc3161'],
      install_requires=[
          'pyasn1',
          'python-dateutil',
          'pyasn1_modules',
          'requests',
          'M2Crypto'])
