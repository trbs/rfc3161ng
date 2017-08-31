=========
rfc3161ng
=========

.. image:: https://img.shields.io/pypi/l/rfc3161ng.svg
   :target: https://raw.githubusercontent.com/trbs/rfc3161ng/master/LICENSE

.. image:: https://travis-ci.org/trbs/rfc3161ng.svg?branch=master
    :alt: Build Status
    :target: https://travis-ci.org/trbs/rfc3161ng

.. image:: https://img.shields.io/pypi/v/rfc3161ng.svg
    :target: https://pypi.python.org/pypi/rfc3161ng/
    :alt: Latest PyPI version

.. image:: https://img.shields.io/pypi/wheel/rfc3161ng.svg
    :target: https://pypi.python.org/pypi/rfc3161ng/
    :alt: Supports Wheel format

A simple client library for cryptographic timestamping service implementing the
protocol from RFC3161.

This started as a fork of https://dev.entrouvert.org/projects/python-rfc3161 and
has some additional patches such as Python3 support.


Example
=======

    >>> import rfc3161ng
    >>> certificate = open('data/certum_certificate.crt', 'rb').read()
    >>> rt = rfc3161ng.RemoteTimestamper('http://time.certum.pl', certificate=certificate)
    >>> tst = rt.timestamp(data=b'John Doe')
    >>> rt.check(tst, data=b'John Doe')
    True
    >>> rfc3161ng.get_timestamp(tst)
    datetime.datetime(2017, 8, 31, 15, 42, 58, tzinfo=tzutc())


Authors
=======

Benjamin Dauvergne <bdauvergne@entrouvert.com>
Michael Gebetsroither <michael@mgeb.org>
Bas van Oostveen <trbs@trbs.net>
