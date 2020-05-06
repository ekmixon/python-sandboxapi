
sandboxapi
==========


.. image:: https://inquest.net/images/inquest-badge.svg
   :target: https://inquest.net/images/inquest-badge.svg
   :alt: Developed by InQuest


.. image:: https://img.shields.io/pypi/v/sandboxapi
   :target: https://img.shields.io/pypi/v/sandboxapi
   :alt: PyPI


.. image:: https://img.shields.io/pypi/pyversions/sandboxapi
   :target: https://img.shields.io/pypi/pyversions/sandboxapi
   :alt: PyPI - Python Version


.. image:: https://img.shields.io/travis/InQuest/python-sandboxapi
   :target: https://img.shields.io/travis/InQuest/python-sandboxapi
   :alt: Travis (.org)


A minimal, consistent API and CLI for building integrations with malware sandboxes.

This library currently supports the following sandbox systems:


* `Cuckoo Sandbox <https://www.cuckoosandbox.org/>`_
* `FireEye AX Series <https://www.fireeye.com/products/malware-analysis.html>`_
* `Joe Sandbox <https://www.joesecurity.org/>`_
* `VMRay Analyzer <https://www.vmray.com/>`_
* `Falcon Sandbox <https://www.falcon-sandbox.com/>`_ (Formerly VxStream)
* `WildFire Sandbox <https://www.paloaltonetworks.com/products/secure-the-network/wildfire>`_

It provides at least the following methods for each sandbox:


* ``is_available()``\ : Check if the sandbox is operable and reachable; returns a boolean.
* ``submit_sample(filepath)``\ : Submit a file for analysis; returns the corresponding ``item_id``.
* ``check_item_status(item_id)``\ : Check if analysis has completed for a file; returns a boolean.
* ``report(item_id)``\ : Retrieve the report for a submitted file as JSON.
* ``score(report)``\ : Parse out and return an integer score in the range of 0 to 10 from the report object.

Some sandbox classes may have additional methods implemented. See inline
documentation for more details.

Features
--------


* A consistent Python API for interacting with the supported sandboxes.
* A command line interface for interacting with the supported sandboxes.
* Support for loading sandbox settings from a config file.

Installation
------------

Install through pip:

.. code-block::

   pip install sandboxapi

Version 2.0.0 and up only supports Python 3.5 and up (RIP Python 2). To continue using python-sandboxapi with Python 2, install version 1.5.

.. code-block::

   pip install sandboxapi==1.5.1

Usage
-----

Basic API usage is as follows:

.. code-block:: python

   import json
   import sys
   import time

   from sandboxapi import apis

   # Connect to the sandbox
   sandbox = apis.CuckooSandbox(host='192.168.0.20', port=8090)

   # Verify connectivity
   if not sandbox.available:
       print('sandbox is down, exiting')
       sys.exit(1)

   # Submit a file
   filepath = './myfile.exe'
   submission_id = sandbox.submit_sample(filepath)
   print("file {} submitted for analysis, ID is {}".format(filepath, submission_id))

   # Wait for the analysis to complete
   while not sandbox.check_item_status(submission_id):
       print('Not done yet, sleeping 10 seconds...')
       time.sleep(10)

   # print the report
   print('Analysis complete. Fetching report...')
   report = sandbox.report(submission_id)
   print(json.dumps(report, indent=4))
   print("Score: {}".format(sandbox.score(report)))

Since the library provides a consistent API, you can treat all sandoxes
the same way:

.. code-block:: python

   import json
   import sys
   import time

   from sandboxapi import CuckooSandbox, FireEyeSandbox, JoeSandbox

   # Connect to the sandbox
   sandboxes = (
       CuckooSandbox(host='192.168.0.20', port=8090)
       FireEyeSandbox(host='192.168.0.21', username='myusername', password='mypassword', environment='winxp-sp3')
       JoeSandbox(host='jbxcloud.joesecurity.org', api_key='mykey')
   )

   for sandbox in sandboxes:
       # Verify connectivity
       if not sandbox.is_available():
           print('Sandbox is down, exiting.')
           sys.exit(1)

       # Submit a file
       filepath = 'myfile.exe'
       submission_id = sandbox.submit_sample(filepath)
       print("file {} submitted for analysis, ID is {}".format(filepath, submission_id))

       # Wait for the analysis to complete
       while not sandbox.check_item_status(submission_id):
           print('Not done yet, sleeping 10 seconds...')
           time.sleep(10)

       # print the report
       print('Analysis complete. Fetching report...')
       report = sandbox.report(submission_id)
       print(json.dumps(report, indent=4))
       print("Score: {}".format(sandbox.score(report)))

You may also be interested in `\ ``malsub`` <https://github.com/diogo-fernan/malsub>`_\ , a similar project with support for a
number of online analysis services.
