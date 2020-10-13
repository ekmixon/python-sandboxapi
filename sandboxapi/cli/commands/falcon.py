"""CLI commands for interacting with the Falcon sandbox."""

import json
from pathlib import Path
import re
import sys

import click

from sandboxapi import FalconSandbox, SandboxError
from sandboxapi.falcon import ANDROID, WIN7, WIN7HWP, WIN7X64, XENIAL


@click.group()
@click.option('--apikey', help='The customer API key for accessing the Falcon sandbox.', type=str)
@click.option('--config', help='The path to a config file to load sandbox settings from.', type=str)
@click.option('--host', help='The hostname of the Falcon server.', type=str)
@click.option(
    '--environment',
    help='The sandbox runtime OS to use.',
    type=click.Choice(['ANDROID', 'WIN7', 'WIN7HWP', 'WIN7X64', 'XENIAL']),
)
@click.option('--proxy', help='The URI of a proxy server to connect through.', type=str, multiple=True)
@click.option('--timeout', help='The delay in seconds before a request times out.', type=int)
@click.option('--ssl/--no-ssl', help='Enables SSL certificate validation.', default=False)
@click.pass_context
def falcon(
        ctx: click.Context,
        apikey: str,
        config: str,
        host: str,
        environment: str,
        proxy: str,
        timeout: str,
        ssl: bool,
) -> None:
    """Falcon sandbox commands."""
    sandbox_args = {}
    if apikey is not None:
        sandbox_args['api_key'] = apikey
    if config is not None:
        sandbox_args['config'] = config
    if host is not None:
        sandbox_args['host'] = host
    if environment is not None:
        env = environment.upper()
        if env == 'ANDROID':
            e = ANDROID
        elif env == 'WIN7':
            e = WIN7
        elif env == 'WIN7HWP':
            e = WIN7HWP
        elif env == 'WIN7X64':
            e = WIN7X64
        elif env == 'XENIAL':
            e = XENIAL
        else:
            e = WIN7X64
        sandbox_args['environment'] = e
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
        ctx.obj = FalconSandbox(**sandbox_args)
    except SandboxError as err:
        click.secho(str(err), err=True, fg='red')
        ctx.exit(20)


@falcon.command(short_help='Check to see if the Falcon sandbox is available.')
@click.pass_context
def available(ctx: click.Context) -> None:
    """Check to see if the Falcon sandbox is up and available."""
    status = ctx.obj.available
    if status:
        click.echo('Falcon sandbox {} is available.'.format(ctx.obj.base_url))
    else:
        click.secho('Falcon sandbox {} is unavailable.'.format(ctx.obj.base_url), err=True, fg='red')
        ctx.exit(1)


@falcon.command(short_help='Submit a sample to the Falcon sandbox.')
@click.option('--file', '-f', help='The path to the file to submit.', type=str, required=True, prompt=True)
@click.pass_context
def submit(ctx: click.Context, file: str) -> None:
    """Submit a sample to the Falcon sandbox."""
    job_id = None
    if not ctx.obj.api_key:
        click.secho('API key is required.')
        ctx.exit(5)
    try:
        job_id = ctx.obj.submit_sample(file)
    except (FileNotFoundError, SandboxError) as err:
        click.secho(str(err), err=True, fg='red')
        if isinstance(err, FileNotFoundError):
            ctx.exit(2)
        else:
            ctx.exit(1)
    click.echo('Submitted successfully. Job id: {}.'.format(job_id))


@falcon.command(short_help='Check the completion status of a job.')
@click.option('--id', 'id_', help='The job ID of the job to check.', type=str, required=True, prompt=True)
@click.pass_context
def check(ctx: click.Context, id_: str) -> None:
    """Check the completion status of a job by ID."""
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
        click.secho('Job {} is complete.'.format(id_), fg='green')
    else:
        click.secho('Job {} is in progress.'.format(id_), fg='yellow')


@falcon.command(short_help='Check how many jobs are pending or running on the Falcon server.')
@click.pass_context
def queue(ctx: click.Context) -> None:
    """Check the number of jobs currently in the sandbox work queue."""
    count = 0
    if not ctx.obj.api_key:
        click.secho('API key is required.')
        ctx.exit(5)
    try:
        count = ctx.obj.queue_size
    except SandboxError as err:
        click.secho(str(err), err=True, fg='red')
        ctx.exit(1)
    if count > 0:
        click.echo('There are currently {} jobs to process.'.format(count))
    else:
        click.echo('There are no pending jobs.')


@falcon.command(short_help='Get the Falcon report for a submitted sample.')
@click.option('--id', 'id_', help='The job ID of the sample.', type=str, required=True, prompt=True)
@click.option('--file', help='Optional file path to save the report to. Only required for PDF format', type=str)
@click.option('--format', 'format_', help='The report format.', type=click.Choice(['json', 'pdf']), default='json')
@click.pass_context
def report(ctx: click.Context, id_: str, file: str, format_: str) -> None:
    """Fetch the analysis report for a sample."""
    output = ''
    if not ctx.obj.api_key:
        click.secho('API key is required.')
        ctx.exit(5)
    try:
        if format_.lower() == 'pdf':
            if not file:
                click.secho('No file specified to save the PDF report.', err=True, fg='red')
                sys.exit(3)
            report_ = ctx.obj.pdf_report(id_)
            output = report_
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
    falcon(obj=None)
