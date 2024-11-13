import os
import re
import sys
import click
import signal
import git as git_
import subprocess

from datetime import datetime
from time import sleep
from git import InvalidGitRepositoryError, GitCommandError

from widevinely.commands import cfg, dl, wvd, keybox
import widevinely.services as services
from widevinely.config import directories, config
from widevinely.commands import cfg, dl, wvd, keybox  # noqa F811
from widevinely.utils import console, logger, clean_line
from widevinely.utils.globals import arguments
from widevinely.utils.exceptions import TitleNotAvailable, NextTitle
from widevinely import __version__, __repository__, __credits__

log = logger.getLogger()

if os.name == "nt":
    import _locale

    _locale._gdl_bak = _locale._getdefaultlocale
    _locale._getdefaultlocale = lambda *args: (_locale._gdl_bak()[0], "UTF-8")


def handler(signum, frame):
    log.exit(f"\n{clean_line}\nCtrl-C was pressed. Process aborted.")


signal.signal(signal.SIGINT, handler)


def delete_link(link, file):
    if not os.path.isfile(file):
        log.exit(f"Cannot delete finished links because {file!r} cannot be found")

    with open(file, "r+") as f:
        lines = f.readlines()

    with open(file, "w+") as f:
        for line in lines:
            if link not in line.strip("\n"):
                f.write(line)

    if args.main.debug:
        log.info_("\nDeleted link of title from linkfile\n")


def parse_links(link, opts: dict = {}):
    for service in services.SERVICE_MAP:
        for alias in services.SERVICE_MAP[service]:
            if opts:
                break
            base_urls = [x for x in dl.commands[service].short_help.split(",")]
            if link.startswith("http"):
                for url in base_urls:
                    url = url.replace(" ", "")
                    if url in link:
                        return service, link
            elif not link.startswith("http"):
                if f"{alias.lower()}:" in link:
                    return service, link.replace(f"{alias.lower()}:", "")

    log.warning_(f"'{link}' is not supported yet\n")
    return None, None


def credits() -> None:
    copyright_years = 2020
    current_year = datetime.now().year
    if copyright_years != current_year:
        copyright_years = f"{copyright_years}-{current_year}"

    try:
        git = git_.Repo(os.getcwd()).remotes[0].repo.git
        latest_commit = git.log("--pretty=%H", "-n", "1")
    except InvalidGitRepositoryError:
        latest_commit = None

    if len(sys.argv) == 1:
        log.info_(
            f"Widevinely version {__version__} Copyright (c) {copyright_years} Playready Widevinely",
            style="bold title",
        )
        log.info_(
            __repository__ + f"{f' - {latest_commit}' if latest_commit else ''}",
            style="bold title",
        )
        exit()

    log.info_(__credits__, style="bold title")
    log.info_(
        " " * 33 + f" v{__version__} Copyright (c) {copyright_years} Playready Widevinely\n",
        style="bold title",
    )


def check_update() -> None:
    """
    Check if there's an update from Widevinely's Github Repository
    It will update to the latest branch (stable|beta|nightly)
    if a personal Github token is available and the update command
    has been invoked or auto_update is enabled in the configuration

    When there's an issue it will return without notice
    if the update command is not invoked
    it will log with an exit or warning otherwise.
    """
    update_command = "update" in sys.argv

    try:
        git = git_.Repo(os.getcwd()).remotes[0].repo.git
    except InvalidGitRepositoryError:
        if update_command:
            log.exit("This Widevinely build does not seem to have a .git folder")
        return

    git.fetch()
    status = git.status()

    if not getattr(config, "github", None):
        if update_command:
            log.exit("Could not find Github details in configuration file")
        return
    elif not config.github.get("auto_update") and not update_command:
        return
    elif not config.github.get("token"):
        if update_command:
            log.exit(
                "\nAdd a personal Github token to the configuration file to continue"
            )
        return

    total_commits = (
        int(re.sub(r"[\sa-zA-Z]", "", re.search(r"by [0-9]+ commit", status).group()))
        if "Your branch is ahead" in status or "Your branch is behind" in status
        else 0
    )

    if status.startswith("fatal") or status.startswith("error"):
        error = status.split("\n")[0].replace("fatal: ", "").replace("error: ", "")
        log.exit(f"\nGithub returned an error: {error!r}")
    elif "Your branch is up to date" in status:
        if update_command:
            log.info_("[green]Widevinely already up to date[/green]")
        return
    elif "Your branch is ahead" in status:
        if update_command:
            log.exit(
                f"\nUpdate aborted. Local git is {total_commits} commits ahead of remote."
            )
        return

    if "Your branch is behind" in status:
        log.info_("")
        with console.status(
            " [green]Pulling missing changes from git remote[/green]"
            if update_command
            else " [green]New update available...[/green]"
        ) as puller:
            try:
                pull = git.pull()
            except GitCommandError:
                log.exit("\nCould not update Widevinely from git remote")

            if pull == "Already up to date.":
                puller.stop()
                if update_command:
                    log.exit("\nUpdate aborted. Widevinely is already up to date.")
                else:
                    log.info_("Widevinely is already up to date.")
                return
            elif "file changed" in pull or "files changed" in pull:
                puller.update(" [green]Verifying pulled git changes[/green]")
                sleep(2)
                puller.update(" [green]Make sure latest poetry is installed[/green]")
                poetry_update = subprocess.run(
                    "pip install poetry==1.2.1",
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    shell=True,
                )
                if poetry_update.returncode:
                    log.exit("Could not install latest poetry version")

                puller.update(" [green]Installing pulled git changes[/green]")
                poetry_install = subprocess.run(
                    "poetry install",
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    shell=True,
                )
                if poetry_install.returncode:
                    log.exit("Could not install latest git changes")
                new_status = git.status()
                if "Your branch is up to date" in new_status:
                    puller.stop()
                    log.info_(
                        f"[green]Successfully pulled {total_commits} commit{'s' if total_commits > 1 else ''} from Widevinely's git remote[/green]"
                    )
                    log.info_("")
                    return

            puller.stop()
            log.exit("Failed updating Widevinely from git remote")
    else:
        log.exit("\nCould not update Widevinely from git remote")


@click.group(invoke_without_command=True)
@click.option(
    "-v", "--version", is_flag=True, default=False, help="Print version information."
)
@click.option(
    "-d", "--debug", is_flag=True, default=False, help="Enable DEBUG level logs."
)
@click.option(
    "--links",
    "links",
    is_flag=True,
    default=False,
    help="Download content provided via a txt file",
)
def main(**main_args) -> None:
    """
    Downloader implementation for downloading
    content from VOD Streaming Services e.g. Netflix
    """
    main_args["help"] = (
        True if any(arg in ["-h", "--help"] for arg in sys.argv) else False
    )

    global args
    args = arguments(main=main_args)

    if not config and not cfg_:
        log.exit("Configuration file could not be found.")

    if "--links" in sys.argv:
        args.main.links = True

    args.main.title = None
    title_id = None
    if dl_ and not args.main.help:
        args_ = ["dl"]
        links, link_file = [], None
        dl_args, service_args = [], []
        sys_args = [arg for arg in sys.argv if arg not in ["-i", "--links"]]

        if args.main.links:
            try:
                link_file = sys.argv[sys.argv.index("--links") + 1]
                link_file = (
                    directories.links / link_file
                    if link_file.endswith(".txt")
                    else directories.links / "links.txt"
                    if not link_file or link_file.startswith("-")
                    else None
                )
            except (IndexError, AttributeError):
                pass

            if not link_file:
                link_file = (
                    directories.links
                    if os.path.isfile(directories.links)
                    else directories.links / "links.txt"
                    if os.path.isfile(directories.links / "links.txt")
                    else None
                )

            if not link_file or not os.path.isfile(link_file):
                log.exit(
                    f"\nCould not find any linkfile in {str(directories.links)!r}\n"
                    "First create one and add some links in it before using the arguments '-i' or '--links'"
                )

            with open(link_file, "r") as f:
                for line in f.readlines():
                    links.append(line.replace("\n", ""))
            links = [link for link in links if link]

            if not links:
                log.exit(f"It looks like file {str(link_file)!r} is empty")
        else:
            for arg in sys.argv:
                for service_ in services.SERVICE_MAP:
                    for alias in services.SERVICE_MAP[service_]:
                        if arg == alias.lower() and sys.argv[
                            sys.argv.index(arg) - 1
                        ] not in [
                            "-al",
                            "--alang",
                            "-sl",
                            "--slang",
                            "-fl",
                            "--flang",
                            "--default-audio",
                            "--default-subtitle",
                            "-p",
                            "--proxy",
                            "-pc",
                            "--proxy-country",
                        ]:
                            service = service_
                            try:
                                title_id = sys.argv[sys.argv.index(arg) + 1]
                            except IndexError:
                                pass

        if not title_id and not args.main.links:
            sys.argv.append("--help")
            run(sys.argv[1:])

        total_links = len(links) if args.main.links else 1
        for link in links if args.main.links else [title_id]:
            args = arguments(main=args.main, reset=True)
            args_ = ["dl"]
            args.main.title = link
            if args.main.links:
                service, title_id = parse_links(link)

            if (
                link.startswith("http")
                and not any(
                    base_url in link
                    for base_url in [
                        x.replace(" ", "")
                        for x in dl.commands[service].short_help.split(",")
                    ]
                )
                and service != "Amazon"
            ):
                log.exit(f"Invalid link for {service}: {link!r}")

            if not service:
                continue

            for dl_args_ in dl.params:
                for dl_arg in dl_args_.opts:
                    dl_args += [dl_arg]

            for sys_arg in sys_args:
                if sys_arg in dl_args:
                    sys_arg_pos = sys_args.index(sys_arg)
                    if sys_arg == "--list":
                        try:
                            if not sys_args[sys_arg_pos + 1].startswith("-"):
                                args_ += ["--list", sys_args[sys_arg_pos + 1]]
                            else:
                                args_ += ["--list", "selected"]
                        except IndexError:
                            args_ += ["--list", "selected"]
                        continue
                    if sys_arg == "--wanted":
                        args_ += ["--wanted", sys_args[sys_arg_pos + 1]]
                        continue
                    args_ += [sys_arg]
                    try:
                        if not sys_args[sys_arg_pos + 1].startswith("-"):
                            args_ += [sys_args[sys_arg_pos + 1]]
                    except IndexError:
                        pass

            args_ += [service]
            args_ += [title_id]

            for service_args_ in dl.commands[service].params:
                for service_arg in service_args_.opts:
                    service_args += [service_arg]

            for sys_arg in sys_args:
                if sys_arg in service_args:
                    sys_arg_pos = sys_args.index(sys_arg)
                    args_ += [sys_arg]
                    try:
                        if not sys_args[sys_arg_pos + 1].startswith("-"):
                            args_ += [sys_args[sys_arg_pos + 1]]
                    except IndexError:
                        pass

            try:
                run(args_)
            except (TitleNotAvailable, NextTitle):
                if args.main.links:
                    log.info_("")
                    delete_link(link, file=link_file)
                    total_links = total_links - 1
                    if total_links == 0:
                        log.info_("\nProcessed All Titles\n", style="title")
                        exit()
    else:
        run(sys.argv[1:])


@click.group(invoke_without_command=True)
@click.pass_context
def run(args_) -> None:
    pass


global dl_, cfg_, wvd_, keybox_
dl_, cfg_, wvd_, keybox_ = (
    False,
    False,
    False,
    False,
)
main.add_command(dl)
main.add_command(cfg)
main.add_command(wvd)
main.add_command(keybox)

run.add_command(dl)
run.add_command(cfg)
run.add_command(wvd)
run.add_command(keybox)

if len(sys.argv) > 1:
    if sys.argv[1].lower() == "dl":
        dl_ = True
    elif sys.argv[1].lower() == "cfg":
        cfg_ = True
    elif sys.argv[1].lower() == "wvd":
        wvd_ = True
    elif sys.argv[1].lower() == "keybox":
        keybox_ = True

credits()
check_update()

if sys.argv[-1] != "update":
    main()

exit()
