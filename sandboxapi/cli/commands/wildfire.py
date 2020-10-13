"""CLI commands for interacting with the Wildfire sandbox."""

import json
from pathlib import Path
import re

import click

from sandboxapi import WildFireSandbox, SandboxError


@click.group()
@click.option('--apikey', help='The customer API key for accessing the WildFire sandbox.', type=str)
@click.option('--config', help='The path to config file to load sandbox settings from.', type=str)
@click.option('--host', help='The hostname of the WildFire server.', type=str)
@click.option('--proxy', help='The URI of a proxy server to connect through.', type=str, multiple=True)
@click.option('--timeout', help='The delay in seconds before a request times out.', type=int)
@click.option('--ssl/--no-ssl', help='Enables SSL certificate validation.', default=False)
@click.pass_context
def wildfire(ctx: click.Context, apikey: str, config: str, host: str, proxy: str, timeout: int, ssl: bool) -> None:
    """WildFire sandbox commands."""
    sandbox_args = {}
    if apikey is not None:
        sandbox_args['api_key'] = apikey
    if config is not None:
        sandbox_args['config'] = config
    if host is not None:
        sandbox_args['host'] = host
    if proxy is not None:
        proxies = {}
        for p in proxy:
            proxies.update({re.match(r'(http[s]?)', p).group(1): p})
        sandbox_args['proxies'] = proxies
    if timeout is not None:
        sandbox_args['timeout'] = timeout
    if ssl:
        sandbox_args['verify_ssl'] = ssl
    try:
        ctx.obj = WildFireSandbox(**sandbox_args)
    except SandboxError as err:
        click.secho(str(err), err=True, fg='red')
        ctx.exit(20)


@wildfire.command(short_help='Check to see if the WildFire sandbox is available.')
@click.pass_context
def available(ctx: click.Context) -> None:
    """Check to see if the WildFire sandbox is up and available."""
    status = ctx.obj.available
    if status:
        click.echo('WildFire sandbox {} is available.'.format(ctx.obj.base_url))
    else:
        click.secho('WildFire sandbox {} is unavailable.'.format(ctx.obj.base_url), err=True, fg='red')
        ctx.exit(1)


@wildfire.command(short_help='Submit a sample to the WildFire sandbox.')
@click.option('--file', '-f', help='The path to the file to submit.', type=str, required=True, prompt=True)
@click.pass_context
def submit(ctx: click.Context, file: str) -> None:
    """Submit a sample to the WildFire sandbox for analysis."""
    task_id = None
    if not ctx.obj.api_key:
        click.secho('API key is required.')
        ctx.exit(5)
    try:
        task_id = ctx.obj.submit_sample(file)
    except (FileNotFoundError, SandboxError) as err:
        click.secho(str(err), err=True, fg='red')
        if isinstance(err, FileNotFoundError):
            ctx.exit(2)
        else:
            ctx.exit(1)
    except SandboxError as err:
        click.secho(err, err=True, fg='red')
    click.echo('Submitted successfully. File hash: {}.'.format(task_id))


@wildfire.command(short_help='Check the completion status of a submission.')
@click.option('--id', 'id_', help='The file hash of the sample to check.', type=str, required=True, prompt=True)
@click.pass_context
def check(ctx: click.Context, id_: str) -> None:
    """Check the completion status of a task by ID."""
    status = None
    if not ctx.obj.api_key:
        click.secho('API key is required.')
        ctx.exit(5)
    try:
        status = ctx.obj.check_item_status(id_)
    except SandboxError as err:
        click.secho(str(err), err=True, fg='red')
        ctx.exit(1)
    if status:
        click.secho('Submission {} is complete.'.format(id_), fg='green')
    else:
        click.secho('Submission {} is in progress.'.format(id_), fg='yellow')


@wildfire.command(short_help='Get the WildFire report for a submitted sample.')
@click.option('--id', 'id_', help='The file hash of the submission to check.', type=str, required=True, prompt=True)
@click.option('--file', help='File path to save the report to. Only required for PDF format.', type=str)
@click.option(
    '--format',
    'format_',
    help='The report format.',
    type=click.Choice(['json', 'pdf', 'xml']),
    default='json',
)
@click.pass_context
def report(ctx: click.Context, id_: str, file: str, format_: str) -> None:
    """Fetch the analysis report for a sample."""
    output = None
    if not ctx.obj.api_key:
        click.secho('API key is required.')
        ctx.exit(5)
    try:
        if format_.lower() == 'pdf':
            if not file:
                click.secho('No file specified to save the PDF report.', err=True, fg='red')
                ctx.exit(3)
            report_ = ctx.obj.pdf_report(id_)
            output = report_
        elif format_.lower() == 'xml':
            report_ = ctx.obj.xml_report(id_)
            output = bytes(report_).decode('utf-8')
        else:
            report_ = ctx.obj.report(id_)
            output = json.dumps(report_, indent=4)
    except SandboxError as err:
        click.secho(str(err), err=True, fg='red')
        ctx.exit(1)
    if file:
        try:
            if format_.lower() == 'pdf':
                Path(file).write_bytes(output)
            else:
                Path(file).write_text(output)
            click.echo('The file was written successfully.')
        except IOError as err:
            click.secho(str(err), err=True, fg='red')
            ctx.exit(2)
    else:
        click.echo(output)


if __name__ == '__main__':
    wildfire(obj=None)
