#!/usr/bin/python
from setuptools import setup

with open('README.rst', 'r') as f:
    long_description = f.read()

setup(
    name='rfc3161ng',
    version='2.1.0',
    license='MIT',
    url='https://dev.entrouvert.org/projects/python-rfc3161',
    description='Python implementation of the RFC3161 specification, using pyasn1',
    long_description=long_description,
    author='Benjamin Dauvergne',
    author_email='bdauvergne@entrouvert.com',
    maintainer='trbs',
    maintainer_email='trbs@trbs.net',
    platforms=['any'],
    classifiers=[
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.6',
        'Topic :: Communications',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    packages=['rfc3161ng'],
    install_requires=[
        'pyasn1',
        'python-dateutil',
        'pyasn1_modules',
        'requests',
        'cryptography',
    ]
)
