# Installation

## Install with pip

```bash
> pip install sandboxapi
```

Version 2.0.0 and up only supports Python 3.5 and up (RIP Python 2). To continue using python-sandboxapi with Python 2, install version 1.5.

```bash
> pip install sandboxapi==1.5.1
```

## Install from GitHub

First, create a new Python 3.5 or up environment to install into:

### venv

```bash
> python -m venv /path/to/env/named/python-sandboxapi
> source /path/to/env/named/python-sandboxapi/bin activate
```

### virtualenv

```bash
> virtualenv /path/to/env/named/python-sandboxapi
> source /path/to/env/named/python-sandboxapi/bin activate
```

### conda

```bash
> conda create --name python-sandboxapi
> conda activate python-sandboxapi
```

Make a directory to install the repository into if needed:

```bash
> mkdir /path/to/destination/directory
> cd /path/to/destination/directory
```

Next, clone the repository with the following command:

```bash
> git clone https://github.com/InQuest/python-sandboxapi.git
```

If using SSH, use the following command instead:

```bash
> git clone git@github.com:InQuest/python-sandboxapi.git
```

Change into the newly cloned directory.

```bash
> cd python-sandboxapi
```

Lastly, install the required packages:

### venv and virtualenv

```bash
> pip install -r requirements.txt
```

### conda

```bash
> conda env update --file environment.yml
```