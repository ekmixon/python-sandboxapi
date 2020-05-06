# Using the API

## Interacting with sandboxes

Sandbox services can take awhile to run because of the time involved for a job to work through the queue, start up a virtual machine, execute the sample, analyze the effects, and generate a report. For this reason, the workflow below should be used for submitting a sample and getting a report or threat score.

<div class="mermaid">
graph TD
A[submit_sample()]
B{analysis complete?}
C[report()]
D[score()]
E[check_item_status()]
A --> |sandbox starts analysis| E
E --> |check analysis status| B
B --> |no| E
B --> |yes| C
C --> |extract threat score| D
</div>

<script src="https://unpkg.com/mermaid@8.4.1/dist/mermaid.min.js"></script>
<script>
    var config = {
        startOnLoad:true,
        flowchart: {
            useMaxWidth:false,
            htmlLabels:true
        }
    }
    mermaid.initialize(config);
</script>

## The Sandbox class

The functions represented in the flowchart above are implemented as methods of a base `Sandbox` class. The implemented methods and properties of the `Sandbox` class are described below:

* `available` - Set to True if the sandbox is reachable and ready to receive commands, otherwise False.
* `submit_sample(filepath)` - Submit a file to the sandbox for analysis and get an item ID back for tracking the progress.
* `check_item_status(item_id)` - Checks the completion progress of the sample associated with an item ID and returns True if a report is ready, otherwise False.
* `report(item_id)` - Fetches the report for the item ID from the sandbox and returns the report as JSON.
* `score(report)` - Parses a JSON report for the submitted sample's threat score.

These methods and properties are common across all the supported sandboxes and make it so that you don't have to worry about the particular details of each sandbox's RESTful API.

There is additional functionality supported for each sandbox in the form of methods, properties, and attributes that belong to each `Sandbox` sub-class. The class diagrams for the `Sandbox` base class and sub-classes is shown below:

<div class="mermaid">
classDiagram
Sandbox <|-- Cuckoo
Sandbox <|-- Falcon
Sandbox <|-- FireEye
Sandbox <|-- Joe
Sandbox <|-- VMRay
Sandbox <|-- WildFire

Sandbox: -dict request_opts
Sandbox: +bool available
Sandbox: +str base_url
Sandbox: +Config config
Sandbox: +dict proxies
Sandbox: +int timeout_secs
Sandbox: +bool verify_ssl
Sandbox: -get_file(filepath)
Sandbox: -generate_config_file(filepath)
Sandbox: -set_attribute(value, default, name)
Sandbox: +submit_sample(filepath)
Sandbox: +check_item_status(item_id)
Sandbox: +report(item_id)
Sandbox: +decode(response)
Sandbox: +score(report)
Sandbox: +delete_item(item_id)

Cuckoo: -dict request_opts
Cuckoo: +int queue_size
Cuckoo: +enqueued()

Falcon: -dict headers
Falcon: +int environment
Falcon: +int queue_size
Falcon: +pdf_report(item_id)

FireEye: -str api_token
FireEye: -HTTPBasicAuth auth
FireEye: -dict headers
FireEye: +bool has_token
FireEye: +str profile
FireEye: -authenticate()
FireEye: +logout()
FireEye: +xml_report(item_id)

Joe: +jbxapi jbx
Joe: + get_webid(item_id)
Joe: +pdf_report(item_id)
Joe: +xml_report(item_id)

VMRay: -dict headers
VMRay: +detailed_report(analysis_id)
VMRay: +top_ranked_analysis(report)

WildFire: -str api_key
WildFire: -get_verdict(item_id)
WildFire: +pdf_report(item_id)
WildFire: +xml_report(item_id)
</div>

<script src="https://unpkg.com/mermaid@8.4.1/dist/mermaid.min.js"></script>
<script>
    var config = {
        startOnLoad:true,
        flowchart: {
            useMaxWidth:false,
            htmlLabels:true
        }
    }
    mermaid.initialize(config);
</script>

For more details on how to use the Sandbox API, refer to the API reference.

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
