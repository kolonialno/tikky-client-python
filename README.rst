tikky-client-python
===================

Unofficial Python wrapper for Tikky.io's HTTP API, with some crypto help sprinkled on top.

Example usage
-------------

Invoke the client's API methods using a context manager to get authorized calls:

.. code:: python

    with tikky_client:
        tikky_client.method()

Auth tokens are kept within each context manager block, so do as much at once as possible
to minimize the number of HTTP calls. Optionally, see __enter__ and __exit__ for examples
of what to replicate if you require more complex auth sessions.

License
-------

tikky-client-python is released under the `MIT License`_.

.. _MIT License: https://opensource.org/licenses/MIT
