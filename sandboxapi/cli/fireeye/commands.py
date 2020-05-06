"""CLI commands for interacting with the FireEye sandbox."""

import json
from pathlib import Path
import re

import click

from sandboxapi import FireEyeSandbox, SandboxError


@click.group()
@click.option('--config', help='The path to a config file to load sandbox settings from.', type=str)
@click.option('--host', help='The hostname of the FireEye server.', type=str)
@click.option('--port', help='The port of the FireEye server.', type=int)
@click.option('--username', help='A valid username.', type=str)
@click.option('--password', help="The FireEye user's password.", type=str)
@click.option(
    '--environment',
    help='The sandbox runtime OS to use.',
    type=click.Choice(['winxp-sp3', 'win7-sp1', 'win7x64-sp1']),
)
@click.option('--legacy/--current', help='Use the FireEye legacy API.', default=False)
@click.option('--proxy', help='The URI of a proxy server to connect through.', type=str, multiple=True)
@click.option('--timeout', help='The delay in seconds before a request times out.', type=int)
@click.option('--ssl/--no-ssl', help='Enables SSL certificate validation.', default=False)
@click.pass_context
def fireeye(
        ctx: click.Context,
        config: str,
        host: str,
        port: int,
        username: str,
        password: str,
        environment: str,
        legacy: bool,
        proxy: str,
        timeout: int,
        ssl: bool,
) -> None:
    """FireEye sandbox commands."""
    sandbox_args = {}
    if config is not None:
        sandbox_args['config'] = config
    if host is not None:
        sandbox_args['host'] = host
    if port is not None:
        sandbox_args['port'] = port
    if username is not None:
        sandbox_args['username'] = username
    if password is not None:
        sandbox_args['password'] = password
    if environment is not None:
        sandbox_args['environment'] = environment
    if legacy:
        sandbox_args['legacy_api'] = legacy
    if proxy is not None:
        proxies = {}
        for p in proxy:
            proxies.update({re.match(r'(http[s]?)', p).group(1): p})
        sandbox_args['proxies'] = proxies
    if timeout is not None:
        sandbox_args['timeout'] = timeout
    if ssl:
        sandbox_args['verify_ssl'] = ssl
    ctx.obj = FireEyeSandbox(**sandbox_args)


@fireeye.command(short_help='Check to see if the FireEye sandbox is available.')
@click.pass_context
def available(ctx: click.Context) -> None:
    """Check to see if the FireEye sandbox is up and available."""
    status = ctx.obj.available
    if status:
        click.echo('FireEye sandbox {} is available.'.format(ctx.obj.base_url))
        ctx.obj.logout()
    else:
        click.secho('FireEye sandbox {} is unavailable.'.format(ctx.obj.base_url), err=True, fg='red')
        ctx.obj.logout()
        ctx.exit(1)


@fireeye.command(short_help='Submit a sample to the FireEye sandbox.')
@click.option('--file', '-f', help='The path to the file to submit.', type=str, required=True, prompt=True)
@click.pass_context
def submit(ctx: click.Context, file: str) -> None:
    """Submit a sample to the FireEye sandbox for analysis."""
    key = None
    try:
        key = ctx.obj.submit_sample(file)
    except (FileNotFoundError, SandboxError) as err:
        click.secho(str(err), err=True, fg='red')
        if isinstance(err, FileNotFoundError):
            ctx.exit(2)
        else:
            ctx.exit(1)
    finally:
        ctx.obj.logout()
    click.echo('Submitted successfully. Submission key: {}.'.format(key))


@fireeye.command(short_help='Check the completion status of a submission.')
@click.option('--id', 'id_', help='The submission key of the job to check.', type=str, required=True, prompt=True)
@click.pass_context
def check(ctx: click.Context, id_: str) -> None:
    """Check the completion status of a job by submission key."""
    status = None
    try:
        status = ctx.obj.check_item_status(id_)
    except SandboxError as err:
        click.secho(str(err), err=True, fg='red')
        ctx.exit(1)
    finally:
        ctx.obj.logout()
    if status:
        click.secho('Submission {} is complete.'.format(id_), fg='green')
    else:
        click.secho('Submission {} is in progress.'.format(id_), fg='yellow')


@fireeye.command(short_help='Get the FireEye report for a submitted sample.')
@click.option('--id', 'id_', help='The submission key of the job to check.', type=str, required=True, prompt=True)
@click.option('--file', help='File path to save the report to. Only required for PDF format', type=str)
@click.option('--format', 'format_', help='The report format.', type=click.Choice(['json', 'xml']), default='json')
@click.pass_context
def report(ctx: click.Context, id_: str, file: str, format_: str) -> None:
    """Fetch the analysis report for a sample."""
    output = ''
    try:
        if format_ == 'xml':
            report_ = ctx.obj.xml_report(id_)
            output = bytes(report_).decode('utf-8')
        else:
            report_ = ctx.obj.report(id_)
            output = json.dumps(report_, indent=4)
    except SandboxError as err:
        click.secho(str(err), err=True, fg='red')
        ctx.exit(1)
    finally:
        ctx.obj.logout()
    if file:
        try:
            Path(file).write_text(output)
        except IOError as err:
            click.secho(str(err), err=True, fg='red')
            ctx.exit(2)
        click.echo('The file was written successfully.')
    else:
        click.echo(output)


if __name__ == '__main__':
    fireeye(obj=None)
