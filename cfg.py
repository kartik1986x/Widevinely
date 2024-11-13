import os
import click

from pathlib import Path
from appdirs import AppDirs
from widevinely.utils import logger

log = logger.getLogger("cfg")

root_config_dir = Path(AppDirs("widevinely", False).user_config_dir)
root_config_dir.mkdir(exist_ok=True, parents=True)
config_file = root_config_dir / "config.yml"


@click.group("cfg", invoke_without_command=True)
@click.pass_context
def cfg(*args):
    if not args[0].invoked_subcommand:
        if os.path.isfile(config_file):
            with open(config_file, "r+") as config_f:
                for line in config_f.readlines():
                    if line.endswith(".yml"):
                        log.success_(
                            f"Current configuration filepath: {line!r}", debug=False
                        )
                        return

        log.warning_("No configuration filepath set yet.")


@cfg.command(
    name="set",
    short_help="Save Widevinely's configuration filepath.",
)
@click.argument("config_path", type=Path)
def set(config_path: Path):
    if not config_path.suffix:
        log.exit("Please provide a configuration file, not a path.")
    elif not str(config_path).endswith(".yml"):
        log.exit("Configuration file is not a YAML file.")
    elif not os.path.isfile(config_path):
        log.exit(
            f"Could not find {str(config_path.name)!r} {f'at {str(config_path.parent)!r}' if str(config_path.parent) != '.' else 'in current path'}"
        )

    if os.path.isfile(config_file):
        with open(config_file, "r+") as config_f:
            for line in config_f.readlines():
                if line == str(config_path):
                    log.warning_(
                        f"Configuration filepath {str(config_path)!r} is already set"
                    )
                    exit()

    with open(config_file, "w+") as config_f:
        config_f.write(str(config_path))

    log.success_("Configuration filepath has been set", debug=False)
