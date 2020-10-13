"""This module hosts the Command Line Interface for working with the sandboxes."""

import click
import sys

from sandboxapi.base import Sandbox
from sandboxapi.cli.commands.cuckoo import cuckoo
from sandboxapi.cli.commands.falcon import falcon
from sandboxapi.cli.commands.fireeye import fireeye
from sandboxapi.cli.commands.joe import joe
from sandboxapi.cli.commands.vmray import vmray
from sandboxapi.cli.commands.wildfire import wildfire


@click.group()
def main() -> None:
    """sandboxapi command line interface."""
    pass


@main.command(short_help='Generate a config file to use for sandbox setting configuration.')
@click.option('--output', '-o', help='The path and filename of the config file - defaults to "./sandbox_config.cfg"')
def generate_config(output: str) -> None:
    """Generate a config file to use for sandbox setting configuration."""
    sandbox = Sandbox()
    try:
        if output:
            sandbox.generate_config_file(output)
        else:
            sandbox.generate_config_file()
    except Exception as err:
        click.secho(str(err), err=True, fg='red')
        click.secho('Could not write the config file.', err=True, fg='red')
        sys.exit(1)
    click.echo('The config file was created successfully.')


if __name__ == '__main__':
    main.add_command(cuckoo)
    main.add_command(falcon)
    main.add_command(fireeye)
    main.add_command(joe)
    main.add_command(vmray)
    main.add_command(wildfire)
    main()
