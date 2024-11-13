import click

from pathlib import Path

from widevinely.utils import logger
from pywidevinely import Keybox

log = logger.getLogger("keybox")


@click.group(
    name="keybox",
    context_settings=dict(
        help_option_names=["-?", "-h", "--help"],
        max_content_width=116,  # max PEP8 line-width, -4 to adjust for initial indent
    ),
)
def keybox():
    """Parsing or Provisioning Widevine Keyboxes."""


@keybox.command()
@click.argument("keybox", type=Path)
@click.pass_context
def parse(ctx, keybox):
    keybox = Keybox.load(keybox)
    log.info_(f"[title]PARSED KEYBOX[/title]\n{repr(keybox)}")


@keybox.command()
@click.argument("keybox", type=Path)
@click.option("-c", "--config", type=Path, default=None, help="Client ID config info.")
@click.option(
    "-o",
    "--output",
    type=Path,
    default=None,
    help="Output directory, defaults to Keybox file directory.",
)
@click.option(
    "-p",
    "--proxy",
    type=str,
    default=None,
    help="Proxy to use when performing requests. Defaults to None.",
)
@click.option(
    "-r",
    "--response",
    is_flag=True,
    default=False,
    help="Save the response from the Provision request in a log file.",
)
@click.option(
    "-s",
    "--skip-test",
    is_flag=True,
    default=False,
    help="Skip testing the provisioned Cdm.",
)
@click.option(
    "-u",
    "--user-agent",
    type=str,
    default=None,
    help="User-Agent to use when performing the request. Defaults to None.",
)
@click.option(
    "-v",
    "--verbose",
    is_flag=True,
    default=False,
    help="Detailed info about the provision process",
)
@click.pass_context
def provision(
    ctx, keybox, config, output, proxy, response, skip_test, user_agent, verbose
):
    """
    Provision a Keybox and receive a Widevine-ready WVD file.
    device_private_key and client_id_blob will also be stored
    in the same directory.
    """
    Keybox.provision(
        keybox, config, output, proxy, response, skip_test, user_agent, verbose
    )
