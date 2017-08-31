==================
Creating a release
==================

:synopsis: Creating a rfc3161ng release


How to make a new release
-------------------------

Run tests::

    $ tox -r

Change version numbers in `setup.py` and `rfc3161ng/__init__.py`::

    $ vi setup.py
    $ vi rfc3161ng/__init__.py
    $ git commit -m 'v2.0.0' setup.py rfc3161ng/__init__.py

Tag it:

    $ git tag 2.0.0

Remove old build directory (if exists)::

    $ rm -r build dist

Prepare the release tarball::

    $ python ./setup.py sdist bdist_wheel

Upload release to pypi::

    $ twine upload -s dist/*

Bumb version number to new in-development pre version::

    $ vi setup.py
    $ vi rfc3161ng/__init__.py
    $ git commit -m 'bumped version number' setup.py rfc3161ng/__init__.py

Push changes back to github::

    $ git push --tags
    $ git push
