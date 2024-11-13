import os
import yaml
from pathlib import Path
from typing import Optional

from pywidevinely import Cdm, Device, serve
from pywidevinely.main import create_device as wvd_create
from pywidevinely.main import migrate as wvd_migrate

import click
from construct import ConstError, ConstructError

from widevinely.utils import logger
from widevinely.scripts import ParseKeybox, ParseClientID

log = logger.getLogger("wvd")


@click.group(
    name="wvd",
    context_settings=dict(
        help_option_names=["-?", "-h", "--help"],
        max_content_width=116,  # max PEP8 line-width, -4 to adjust for initial indent
    ),
)
def wvd():
    """Manage configuration and creation of v2 WVD (Widevine Device) files."""


@wvd.command(name="parse")
@click.argument("type", type=str)
@click.argument("path", type=Path)
@click.option(
    "-v", "--verbose", is_flag=True, default=False, help="Detailed info about WVD file"
)
def parse(type: str, path: Path, verbose: bool):
    """
    Parse a .WVD Widevine Device file or Keybox to check information less verbose.

    If the path is relative, with no file extension,
    it will parse the WVD in the WVDs directory.

    When using argument --verbose it will print as much details as it can
    """
    if type.lower() == "keybox":
        ParseKeybox.parse(path)
        return
    elif type.lower() in ["clientid", "client_id"]:
        ParseClientID.parse(path)
        return

    path = path.parent / f"{path.name.replace('.wvd', '')}"

    if not os.path.isfile(f"{path}.wvd"):
        path = path / f"{path.name}.wvd"
        if not os.path.isfile(path):
            log.exit(
                f"Could not find any file called '{path.name}.wvd' in directory\n{str(path.parent)!r}"
            )

    try:
        device = Device.load(path)
    except ConstError:
        log.warning_("CDM WVD device migrated to version 2\n")
        try:
            migrated_device = Device.migrate(open(path, "rb+").read())
        except (ConstructError, ValueError) as e:
            log.exit(f" - {e}")

        migrated_device.dump(path)
        device = Device.load(os.path.join(path))

    cdm = Cdm.from_device(device=device)
    cdm.api = False

    log.info_(
        f"INFORMATION ABOUT {path.name.upper().replace('.WVD', '')}", style="title"
    )
    Cdm.test(
        "wvd",
        cdm,
        verbose=verbose,
    )


@wvd.command()
@click.option(
    "-t",
    "--type",
    "type_",
    type=click.Choice([x.name for x in Device.Types], case_sensitive=False),
    required=True,
    help="Device Type",
)
@click.option(
    "-l",
    "--level",
    type=click.IntRange(1, 3),
    required=True,
    help="Device Security Level",
)
@click.option(
    "-k",
    "--private_key",
    type=Path,
    required=True,
    help="Device RSA Private Key in PEM or DER format",
)
@click.option(
    "-c",
    "--client_id",
    type=Path,
    required=True,
    help="Widevine ClientIdentification Blob file",
)
@click.option(
    "-v",
    "--vmp",
    type=Path,
    default=None,
    help="Widevine FileHashes Blob file (VMP Blob)",
)
@click.option("-o", "--output", type=Path, default=None, help="Output Directory")
@click.pass_context
def create_device(
    ctx: click.Context,
    type_: str,
    level: int,
    private_key: Path,
    client_id: Path,
    vmp: Optional[Path] = None,
    output: Optional[Path] = None,
) -> None:
    """
    Create a Widevine Device (.wvd) file from an RSA Private Key (PEM or DER) and Client ID Blob.
    Optionally also a VMP (Verified Media Path) Blob, which will be stored in the Client ID.
    """
    wvd_create(
        [
            "--type",
            type_,
            "--level",
            level,
            "--private_key",
            private_key,
            "--client_id",
            client_id,
            "--vmp",
            vmp,
            "--output",
            output,
        ]
    )


@wvd.command()
@click.argument("path", type=str)
@click.option(
    "-v", "--verbose", is_flag=True, default=False, help="Detailed info about WVD file"
)
@click.pass_context
def migrate(ctx: click.Context, path: str, verbose: bool) -> None:
    """
    Upgrade from earlier versions of the Widevine Device (.wvd) format.

    The path argument can be a direct path to a Widevine Device (.wvd) file,
    or a path to a folder of Widevine Devices files.

    The migrated devices are saved to its original location, overwriting the old version.
    """
    migrate_command = [path]
    if verbose:
        migrate_command += ["--verbose"]
    wvd_migrate(migrate_command)


@wvd.command()
@click.argument("config", type=Path)
@click.option("-h", "--host", type=str, default="127.0.0.1", help="Host to serve from.")
@click.option("-p", "--port", type=int, default=8786, help="Port to serve from.")
@click.pass_context
def api(ctx: click.Context, config: Path, host: str, port: int):
    """
    Serve your local Cdms and Widevine Devices Remotely.

    \b
    [CONFIG] is a path to a api config file.
    See `cdm_api_example.yml` for an example config file.

    \b
    Host as 127.0.0.1 may block remote access even if port-forwarded.
    Instead, use 0.0.0.0 and ensure the TCP port you choose is forwarded.
    """
    config = yaml.safe_load(config.read_text(encoding="utf8"))
    serve.run(config, host, port, privacy=True)
