"""This module hosts the Command Line Interface for working with the sandboxes."""

from pathlib import Path
import sys

import click

current_path = str(Path(sys.path[0]).parent.parent)
sys.path.insert(0, str(current_path))
from sandboxapi.cli.cuckoo.commands import cuckoo
from sandboxapi.cli.falcon.commands import falcon
from sandboxapi.cli.fireeye.commands import fireeye
from sandboxapi.cli.joe.commands import joe
from sandboxapi.cli.vmray.commands import vmray
from sandboxapi.cli.wildfire.commands import wildfire


@click.group()
def main() -> None:
    """sandboxapi command line interface."""
    pass


if __name__ == '__main__':
    main.add_command(cuckoo)
    main.add_command(falcon)
    main.add_command(fireeye)
    main.add_command(joe)
    main.add_command(vmray)
    main.add_command(wildfire)
    main()
