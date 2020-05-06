# sandboxapi

![Developed by InQuest](https://inquest.net/images/inquest-badge.svg)
![PyPI](https://img.shields.io/pypi/v/sandboxapi)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/sandboxapi)
![Travis (.org)](https://img.shields.io/travis/InQuest/python-sandboxapi)

A minimal, consistent API and CLI for building integrations with malware sandboxes.

This library currently supports the following sandbox systems:

* [Cuckoo Sandbox](https://www.cuckoosandbox.org/)
* [FireEye AX Series](https://www.fireeye.com/products/malware-analysis.html)
* [Joe Sandbox](https://www.joesecurity.org/)
* [VMRay Analyzer](https://www.vmray.com/)
* [Falcon Sandbox](https://www.falcon-sandbox.com/) (Formerly VxStream)
* [WildFire Sandbox](https://www.paloaltonetworks.com/products/secure-the-network/wildfire)

It provides at least the following methods for each sandbox:

* `is_available()`: Check if the sandbox is operable and reachable; returns a boolean.
* `submit_sample(filepath)`: Submit a file for analysis; returns the corresponding `item_id`.
* `check_item_status(item_id)`: Check if analysis has completed for a file; returns a boolean.
* `report(item_id)`: Retrieve the report for a submitted file as JSON.
* `score(report)`: Parse out and return an integer score in the range of 0 to 10 from the report object.

Some sandbox classes may have additional methods implemented. See inline
documentation for more details.

## Features

* A consistent Python API for interacting with the supported sandboxes.
* A command line interface for interacting with the supported sandboxes.
* Support for loading sandbox settings from a config file.

## Installation

Install through pip:

```bash
pip install sandboxapi
```

Version 2.0.0 and up only supports Python 3.5 and up (RIP Python 2). To continue using python-sandboxapi with Python 2, install version 1.5.

```bash
pip install sandboxapi==1.5.1
```

## API Usage

Basic API usage is as follows:

```python
import json
import sys
import time

import sandboxapi

# Connect to the sandbox
sandbox = sandboxapi.CuckooSandbox(host='192.168.0.20', port=8090)

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
```

Since the library provides a consistent API, you can treat all sandoxes
the same way:

```python
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
```

You may also be interested in [`malsub`](https://github.com/diogo-fernan/malsub), a similar project with support for a
number of online analysis services.

## CLI Usage

Version 2.0.0 and up of python-sandboxapi features a CLI for issuing simple commands to any of the supported sandboxes. For example:

_Check to make sure Joe Sandbox is available:_

```bash
> sandboxcli joe available --apikey mykey

True
```

Note: The default host for Joe Sandbox is `jbxcloud.joesecurity.org` but a different host can be defined explicitly with the `--host` key.

_Submit `myfile.exe` to Joe for analysis:_

```bash
> sandboxcli joe submit \
--apikey mykey \
--host jbxcloud.joesecurity.org \
--file myfile.exe

1123
```

_Check to see if the analysis is complete:_

```bash
> sandboxcli joe check 1123 --apikey mykey

True
```

_Save the JSON report to a file:_

```bash
> sandboxcli joe report 1123 --apikey mykey > myfile_report.json
```

_Save the report as a PDF:_

```bash
> sandboxcli joe report 1123 \
--apikey mykey \
--format pdf > myfile_report.pdf
```

Note: Not all sandboxes support PDF format. Refer to the API documentation for each sandbox to confirm which sandboxes support PDF and XML report formats.

_Typing the `sandboxcli` command without arguments will display the usage:_

```none
> sandboxcli

usage: sandboxcli [-h] [--apikey API_KEY] [--config CONFIG]
                  [--environment ENVIRONMENT] [--file FILE]
                  [--format {json,pdf,xml}] [--host HOST] [--item ITEM]
                  [--legacy] [--password PASSWORD] [--port PORT]
                  [--scheme {http,https}] [--timeout TIMEOUT]
                  [--username USERNAME] [--verify] [--proxy PROXY]
                  {cuckoo,falcon,fireeye,joe,vmray,wildfire}
                  {available,submit,check,report}

Command line interface for sandboxcli.

positional arguments:
  {cuckoo,falcon,fireeye,joe,vmray,wildfire}
                        The sandbox service to use.
  {available,submit,check,report}
                        The command to issue to the sandbox.

optional arguments:
  -h, --help            show this help message and exit
  --apikey API_KEY      The customer API key for accessing the specified
                        sandbox.
  --config CONFIG       The config file to use for loading sandbox properties.
  --environment ENVIRONMENT
                        The OS environment the specified sandbox should use
                        for analysing a sample.
  --file FILE           The path to a sample file to submit the the specified
                        sandbox for analysis.
  --format {json,pdf,xml}
                        The sample analysis report format.
  --host HOST           The hostname of the specified sandbox.
  --item ITEM           The item ID of the submitted sample.
  --legacy              Use the specified sandbox's legacy API.
  --password PASSWORD   The password for authenticating access to the
                        specified sandbox.
  --port PORT           The port the specified sandbox is running on.
  --scheme {http,https}
                        Determines whether to use http or https.
  --timeout TIMEOUT     The number of seconds to wait for a response from the
                        specified sandbox before raising an exception.
  --username USERNAME   The username for authenticating access to the
                        specified sandbox.
  --verify              Verify SSL certificate.
  --proxy PROXY         A proxy to connect through.
```

## Backwards Compatibility

Version 2.0.0 introduces new features and is a completely refactored codebase compared to previous versions. The < 2.0.0 sandbox classes, methods, and arguments are now deprecated but will still be supported for the forseeable future.

If you currently have an application that uses `python-sandboxapi`, refer to the list below:

* My application is in Python 2: Don't upgrade and continue using a 1.x version of `python-sandboxapi`. Pypi shouldn't try to download the newest version with Python 2.
* My application is in Python 3: Be careful about upgrading to version 2.0.0. Some features might not be backwards compatible and could break your application. If you encounter any problems with backwards compatibility, please raise a new issue. Also, consider switching to the new sandbox API which will be regularly updated.
* I'm evaluating `python-sandboxapi` but haven't integrated it into an application yet: Version 2.0.0 was made for you! You can use the new CLI to test out your sandbox integration and later use the API for integrating `python-sandboxapi` into your application.
* I don't care about the API, I'm only want to use the CLI from the command line: Version 2.0.0 is the one for you! No need to worry about backwards compatibility.
