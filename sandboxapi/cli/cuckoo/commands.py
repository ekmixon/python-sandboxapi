"""CLI commands for interacting with the Cuckoo sandbox."""

import json
from pathlib import Path
import re

import click

from sandboxapi import CuckooSandbox, SandboxError


@click.group()
@click.option('--config', help='The path to a config file to load sandbox settings from.', type=str)
@click.option('--host', help='The hostname of the Cuckoo server.', type=str)
@click.option('--port', help='The port of the Cuckoo server.', type=int)
@click.option('--username', help='A valid username if using authentication.', type=str)
@click.option('--password', help="The Cuckoo user's password.", type=str)
@click.option('--https/--http', help='Use https.', default=False)
@click.option('--proxy', help='The URI of a proxy server to connect through.', type=str, multiple=True)
@click.option('--timeout', help='The delay in seconds before a request times out.', type=int)
@click.option('--ssl/--no-ssl', help='Enables SSL certificate validation.', default=False)
@click.pass_context
def cuckoo(
        ctx: click.Context,
        config: str,
        host: str,
        port: int,
        username: str,
        password: str,
        https: bool,
        proxy: str,
        timeout: int,
        ssl: bool,
) -> None:
    """Cuckoo sandbox commands."""
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
    if https:
        sandbox_args['use_https'] = https
    if proxy is not None:
        proxies = {}
        for p in proxy:
            proxies.update({re.match(r'(http[s]?)', p).group(1): p})
        sandbox_args['proxies'] = proxies
    if timeout is not None:
        sandbox_args['timeout'] = timeout
    if ssl:
        sandbox_args['verify_ssl'] = ssl
    ctx.obj = CuckooSandbox(**sandbox_args)


@cuckoo.command(short_help='Check to see if the Cuckoo sandbox is available.')
@click.pass_context
def available(ctx: click.Context) -> None:
    """Check to see if the Cuckoo sandbox is up and available."""
    status = ctx.obj.available
    if status:
        click.echo('Cuckoo sandbox {} is available.'.format(ctx.obj.base_url))
    else:
        click.secho('Cuckoo sandbox {} is unavailable.'.format(ctx.obj.base_url), err=True, fg='red')
        ctx.exit(1)


@cuckoo.command(short_help='Submit a sample to the Cuckoo sandbox.')
@click.option('--file', '-f', help='The path to the file to submit.', type=str, required=True, prompt=True)
@click.pass_context
def submit(ctx: click.Context, file: str) -> None:
    """Submit a sample to the Cuckoo sandbox for analysis."""
    task_id = None
    try:
        task_id = ctx.obj.submit_sample(file)
    except (FileNotFoundError, SandboxError) as err:
        click.secho(str(err), err=True, fg='red')
        if isinstance(err, FileNotFoundError):
            ctx.exit(2)
        else:
            ctx.exit(1)
    click.echo('Submitted successfully. Task id: {}.'.format(task_id))


@cuckoo.command(short_help='Check the completion status of a task.')
@click.option('--id', 'id_', help='The task ID of the task to check.', type=str, required=True, prompt=True)
@click.pass_context
def check(ctx: click.Context, id_: str) -> None:
    """Check the completion status of a task by ID."""
    status = None
    try:
        status = ctx.obj.check_item_status(id_)
    except SandboxError as err:
        click.secho(str(err), err=True, fg='red')
        ctx.exit(1)
    if status:
        click.secho('Task {} is complete.'.format(id_), fg='green')
    else:
        click.secho('Task {} is in progress.'.format(id_), fg='yellow')


@cuckoo.command(short_help='Delete a task from the Cuckoo sandbox queue.')
@click.option('--id', 'id_', help='The task ID of the task to delete.', type=str, required=True, prompt=True)
@click.pass_context
def delete(ctx: click.Context, id_: str) -> None:
    """Remove a task from the Cuckoo sandbox queue by ID."""
    status = None
    try:
        status = ctx.obj.delete_item(id_)
    except SandboxError as err:
        click.secho(str(err), err=True, fg='red')
        ctx.exit(1)
    if status:
        click.echo('Task {} was deleted successfully.'.format(id_))
    else:
        click.secho('Failed to delete task {}.'.format(id_), err=True, fg='red')
        ctx.exit(2)


@cuckoo.command(short_help='Check how many tasks are pending or running on the Cuckoo server.')
@click.pass_context
def queue(ctx: click.Context) -> None:
    """Check the number of tasks currently in the sandbox work queue."""
    count = 0
    try:
        count = ctx.obj.queue_size
    except SandboxError as err:
        click.secho(str(err), err=True, fg='red')
        ctx.exit(1)
    if count > 0:
        click.echo('There are currently {} tasks to process.'.format(count))
    else:
        click.echo('There are no pending tasks.')


@cuckoo.command(short_help='Get the Cuckoo report for a submitted sample.')
@click.option('--id', 'id_', help='The task ID of the sample.', type=str, required=True, prompt=True)
@click.option('--file', help='Optional file path to save the report to.', type=str)
@click.pass_context
def report(ctx: click.Context, id_: str, file: str) -> None:
    """Fetch the analysis report for a sample."""
    output = ''
    try:
        report_ = ctx.obj.report(id_)
        output = json.dumps(report_, indent=4)
    except SandboxError as err:
        click.secho(str(err), err=True, fg='red')
        ctx.exit(1)
    if file:
        try:
            Path(file).write_text(output)
            click.echo('The file was written successfully.')
        except IOError as err:
            click.secho(str(err), err=True, fg='red')
            ctx.exit(2)
    else:
        click.echo(output)


if __name__ == '__main__':
    cuckoo(obj=None)
