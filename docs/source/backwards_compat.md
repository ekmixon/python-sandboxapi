# Backwards Compatibility

Version 2.0.0 introduces new features and is a completely refactored codebase compared to previous versions. The < 2.0.0 sandbox classes, methods, and arguments are now deprecated but will still be supported for the forseeable future.

If you currently have an application that uses `python-sandboxapi`, refer to the list below:

* My application is in Python 2: Don't upgrade and continue using a 1.x version of `python-sandboxapi`. Pypi shouldn't try to download the newest version with Python 2.
* My application is in Python 3: Be careful about upgrading to version 2.0.0. Some features might not be backwards compatible and could break your application. If you encounter any problems with backwards compatibility, please raise a new issue. Also, consider switching to the new sandbox API which will be regularly updated.
* I'm evaluating `python-sandboxapi` but haven't integrated it into an application yet: Version 2.0.0 was made for you! You can use the new CLI to test out your sandbox integration and later use the API for integrating `python-sandboxapi` into your application.
* I don't care about the API, I only want to use the CLI from the command line: Version 2.0.0 is the one for you! No need to worry about backwards compatibility.

## Migrating to version 2

In version 1, all sandbox classes can be found in the `sandboxapi` package. The package structure looks like this:

```text
sandboxapi
├── cuckoo
│   └── CuckooAPI
├── falcon
│   └── FalconAPI
├── fireeye
│   └── FireEyeAPI
├── joe
│   └── JoeAPI
├── vmray
│   └── VMRayAPI
└── wildfire
    └── WildFireAPI
```

For example, to import the `CuckooAPI` class in your Python module, you would write:

```python
from sandboxapi.cuckoo import CuckooAPI
```

In version 2, the new sandbox classes can be imported directly from `sandboxapi`:

```text
sandboxapi
├── CuckooSandbox
├── FalconSandbox
├── FireEyeSandbox
├── JoeSandbox
├── VMRaySandbox
└── WildFireSandbox
```

To import the `CuckooSandbox` class (which is a replacement for `CuckooAPI`), you would write:

```python
from sandboxapi import CuckooSandbox
```

To support backwards compatibility, the `sandboxapi` package with it's modules and classes are available in version 2. However, the classes inherit from the new sandbox classes instead of using the original codebase from version 1. This is because some of the dependencies have changed and aren't backwards compatible.

This might lead to some unexpected behavior when using the backwards compatible classes so use with caution and try to migrate to the new classes as soon as possible.