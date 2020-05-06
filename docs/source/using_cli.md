# Using the CLI

The python-sandboxapi package has a built-in command line interface for calling the common sandbox functions.

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

Command line interface for sandboxcii.

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