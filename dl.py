from __future__ import annotations

import html
import shutil
import os
import click
from widevinely.utils.globals import cdm as cdm_

from threading import Thread
from http.cookiejar import MozillaCookieJar
from pathlib import Path

from typing import Optional

from pywidevinely import Cdm
from pywidevinely import Key
from pywidevinely import Session

from pymediainfo import MediaInfo
from subprocess import *
from langcodes import *
from time import *

from widevinely.utils.globals import arguments
from widevinely.config import Config, credentials, directories, filenames
import widevinely.services as services
from widevinely.config import config
from widevinely.objects import (
    Credential,
    TextTrack,
    Title,
    Titles,
    VideoTrack,
    AudioTrack,
    MenuTrack,
)
from widevinely.objects.vaults import InsertResult, Vaults
from widevinely.utils import logger, clean_line
from widevinely.utils.click import (
    AliasedGroup,
    ContextData,
    proxy_service_param,
    audio_codec,
    audio_channels,
    language_param,
    video_quality,
    video_range,
    video_codec,
    wanted_param,
)
from widevinely.utils.collections import as_list, merge_dict
from widevinely.utils.io import load_yaml
from widevinely.utils.exceptions import *
from widevinely.objects.tracks import Tracks
from widevinely.utils.streamfab import StreamFab

log = logger.getLogger("dl")


def get_service_config(service) -> dict:
    """Get both Service Config and Service Secrets as one merged dictionary."""
    service_config = load_yaml(filenames.service_config.format(service=service))

    user_config = load_yaml(
        filenames.user_service_config.format(service=service)
    ) or load_yaml(filenames.user_service_config.format(service=service))

    if user_config:
        merge_dict(service_config, user_config)

    return service_config


def get_profile(ctx, service, zone, region, profile=None) -> Optional[str]:
    """
    Get profile for Service from config file.
    It also allows selection by zone if the profile config for the service is zoned.
    If it's zoned but no zone choice has been passed, then one will be gotten interactively.
    """
    profiles = config.profiles.get(service)
    if profiles is False:
        return None  # auth-less service if `false` in config
    if not profiles:
        profiles = config.profiles.get("default")
    if profiles == "service":
        profile = zone if zone else service

    if not region:
        for arg in ctx.args:
            if arg == "--region":
                region = ctx.args[ctx.args.index(arg) + 1]

    if not profile:
        if isinstance(profiles, dict):
            if zone and zone in profiles:
                if region and region in profiles[zone]:
                    profile = profiles[zone][region]
                else:
                    profile = profiles[zone]
            if region and region in profiles:
                profile = profiles[region]
        elif isinstance(profiles, str):
            profile = profiles

    if not profile:
        log.exit(
            f"No profile has been defined for {region!r} in the configuration file."
        )

    return profile


def get_cookie_jar(service, profile):
    """Get the profile's cookies if available."""
    cookie_file = os.path.join(
        directories.cookies,
        service.lower() if profile != "primevideo" else "primevideo",
        f"{profile}.txt",
    )
    if not os.path.isfile(cookie_file):
        cookie_file = os.path.join(
            directories.cookies,
            service if profile != "primevideo" else "PrimeVideo",
            f"{profile}.txt",
        )
    if os.path.isfile(cookie_file):
        cookie_jar = MozillaCookieJar(cookie_file)
        with open(cookie_file, "r+", encoding="utf-8") as fd:
            unescaped = html.unescape(fd.read())
            fd.seek(0)
            fd.truncate()
            fd.write(unescaped)
        cookie_jar.load(ignore_discard=True, ignore_expires=True)
        return cookie_jar
    return None


def get_credentials(ctx, service, profile="default", zone="en", region="en"):
    """Get the profile's credentials if available."""
    creds = credentials.get(service, {})

    if isinstance(creds, dict):
        creds = creds.get(region) or creds.get(zone) or creds.get(profile)
        if not creds:
            for arg in ctx.args:
                if arg == "--region":
                    region = ctx.args[ctx.args.index(arg) + 1]
                    try:
                        creds = creds[region]
                    except TypeError:
                        pass

    if creds:
        if isinstance(creds, list):
            return Credential(*creds)
        else:
            return Credential.loads(creds)


def set_service_args(service):
    try:
        serv_args = [
            dict(config.arguments._store)[x]
            for x in dict(config.arguments._store)
            if x == service.lower()
        ][0][1]

        for arg in vars(args.dl):
            if not getattr(args.dl, arg):
                if serv_args and serv_args.get(arg):
                    vars(args.dl)[arg] = serv_args.get(arg)

        if not args.dl.proxy_service and config.proxies.get("default_service"):
            args.dl.proxy_service = config.proxies["default_service"]

        if not args.dl.proxy_country and config.proxies.get("default_country"):
            args.dl.proxy_country = config.proxies["default_country"]
    except IndexError:
        return


def get_content_keys(
    title, titles, ctx, service, service_name, white_space: Optional[str] = ""
):
    vaults = []
    cached_keys = []
    content_keys = []
    StreamFabCache = ""

    for vault in config.key_vaults:
        if not args.dl.no_cache:
            try:
                vaults.append(Config.load_vault(vault))
            except Exception:
                log.warning_(
                    f"Failed to connect to [italic]{vault['name']} {vault['type'].upper()}[/italic] Key Vault"
                )

    ctx.obj.vaults = Vaults(
        vaults, service=service_name, key_policy=ctx.obj.config.get("key_policy")
    )

    for track in title.tracks:
        if track.encrypted:
            if content_keys:
                for x in content_keys:
                    if track.kid == x[0]:
                        track.key = x[1]
            if cached_keys:
                for x in cached_keys:
                    if track.kid == x[0]:
                        track.key = x[1]

            if not args.dl.no_cache and not track.key:
                """Check if KID is in one of the Key Vaults"""
                track.key, vault_used = ctx.obj.vaults.get(title, track)
                if not track.key:
                    keys = StreamFab.cache(title, track, service.session, service)
                    if keys:
                        StreamFabCache = "StreamFab's Key Vault"
                        for kid, key in keys.items():
                            if track.kid == kid:
                                track.key = key
                            if not cached_keys or not any(
                                key in x[1] for x in cached_keys
                            ):
                                log.info_(
                                    white_space
                                    + f"- [green]{kid}:{key}[/green] [cyan]{StreamFabCache}[/cyan]"
                                )
                                cached_keys.append(
                                    (kid, key, StreamFabCache.replace(",", ""))
                                )

                if (
                    track.key
                    and not StreamFabCache
                    or track.key
                    and not any(track.key in x[1] for x in cached_keys)
                ):
                    if track.kid == "0" * 32 or track.key == "0" * 32:
                        log.info_(
                            white_space
                            + f" x [red]{track.kid}:{track.key}[/red] [cyan]{vault_used.name} {vault_used.type.name} Key Vault[/cyan]"
                        )
                        exit()
                    if not cached_keys or not any(
                        track.key in x[1] for x in cached_keys
                    ):
                        log.info_(
                            white_space
                            + f"- [green]{track.kid}:{track.key}[/green] [cyan]{vault_used.name} {vault_used.type.name} Key Vault[/cyan]"
                        )
                        cached_keys.append(
                            (
                                track.kid,
                                track.key,
                                f"{vault_used.name} {vault_used.type.name}",
                            )
                        )

            if not args.dl.cache and not track.key:
                """KID not found, trying to do a license request"""
                if args.dl.cdm == "StreamFabCdm" or cdm.system_id == 21889:
                    keys = StreamFab.Cdm(
                        title,
                        track,
                        service.session,
                        service,
                        certificate=ctx.obj.config.get("certificate")
                        or cdm.common_privacy_cert,
                    )
                else:
                    cdm.session_id = cdm.open()
                    cdm.set_service_certificate(
                        cdm.session_id,
                        service.certificate(
                            challenge=cdm.service_certificate_challenge,
                            title=title,
                            track=track,
                            session_id=cdm.session_id,
                        )
                        or cdm.common_privacy_cert,
                    )

                    licensing = cdm.parse_license(
                        cdm.session_id,
                        service.license(
                            challenge=cdm.get_license_challenge(
                                session_id=cdm.session_id,
                                pssh=track.pssh,
                                type_="STREAMING",
                            ),
                            title=title,
                            track=track,
                            session_id=cdm.session_id,
                        ),
                    )

                    if licensing == "chromecdm_fallback":
                        args.dl.chromecdm_fallback = True
                        keys = get_content_keys(
                            title, titles, ctx, service, service_name, white_space
                        )
                    else:
                        keys = [
                            (x.kid.hex, x.key.hex())
                            for x in cdm.get_keys(
                                session_id=cdm.session_id, type_="CONTENT"
                            )
                        ]

                if not keys:
                    log.exit(
                        white_space
                        + " x No content keys were returned by the License Server..."
                    )

                if args.main.debug:
                    log.info_(
                        white_space
                        + f" + Obtained content keys from the {cdm.device.__class__.__name__} CDM"
                    )

                for kid, key in keys:
                    if kid == "b770d5b4bb6b594daf985845aae9aa5f":
                        # Amazon HDCP test key
                        log.info_(
                            white_space
                            + f"- [red]{kid}:{key}[/red] [cyan]{StreamFabCache}Amazon HDCP test key[/cyan]"
                        )
                        continue
                    if kid == "0" * 32 or key == "0" * 32:
                        # Unusable for decryption
                        log.info_(
                            white_space
                            + f"- [red]{kid}:{key}[/red] [cyan]License Server[/cyan]"
                        )
                        continue
                    if kid == track.kid:
                        track.key = key
                    log.info_(
                        white_space
                        + f"- [green]{kid}:{key}[/green] [cyan]License Server[/cyan]"
                    )
                    if not content_keys or not any(key in x[1] for x in content_keys):
                        content_keys.append((kid, key, "License Server"))

            if not track.key:
                log.exit(
                    white_space + f"- No content key with KID {track.kid} was returned"
                )

    if not args.dl.no_cache:
        if cached_keys:
            content_keys.extend(cached_keys)
            del cached_keys

    if not args.dl.keys:
        for kid, key, source in content_keys:
            if cdm.session_id not in cdm._Cdm__sessions:
                cdm._Cdm__sessions[cdm.session_id] = Session(
                    len(cdm._Cdm__sessions) + 1
                )

            cdm._Cdm__sessions[cdm.session_id].keys.append(
                Key(
                    kid=Key.kid_to_uuid(bytes.fromhex(kid)),
                    key=bytes.fromhex(key),
                    permissions=[],
                    type_="CONTENT",
                )
            )

    if not args.dl.no_cache:
        total_cached, total_exists = 0, 0
        for vault in ctx.obj.vaults.vaults:
            vault.cached, cached, already_exists = 0, 0, 0
            for kid, key, key_type in content_keys:
                if key_type == f"{vault.name} {vault.type.name}":
                    already_exists += 1
                    total_exists += 1
                else:
                    result = ctx.obj.vaults.insert_key(vault, title, track, kid, key)
                    if result == InsertResult.FAILURE:
                        log.exit(
                            white_space
                            + f"- Failed, table {service_name} does not exists in {vault.name} {vault.type} Key Vault"
                        )
                    elif result == InsertResult.SUCCESS:
                        cached += 1
                        total_cached += 1
                    elif result == InsertResult.ALREADY_EXISTS:
                        already_exists += 1
                        total_exists += 1
                    ctx.obj.vaults.commit(vault)

            if cached:
                vault.cached = cached
                if already_exists and args.main.debug:
                    log.info_(
                        white_space
                        + f"  - Skipped caching {already_exists} usable key{'s' if cached > 1 else ''} because {'they' if cached > 1 else 'it'} already exists in [italic]{vault.name} {vault.type.name}[/italic] Key Vault"
                    )
            elif args.main.debug:
                log.info_(
                    white_space
                    + f"  - Did not save any usable key to [italic]{vault.name} {vault.type.name}[/italic] Key Vault because it already exists",
                    debug=True,
                )

            if cached and already_exists:
                if cached + already_exists < len(content_keys):
                    log.exit(
                        white_space
                        + f"  x Failed to cache {len(content_keys) - cached - already_exists} keys to [italic]{vault.name} {vault.type.name}[/italic] Key Vault"
                    )

            if already_exists != len(content_keys):
                log.info_(
                    white_space
                    + f"+ Cached {len(content_keys) - already_exists}/{len(content_keys)} keys to {vault.name} {vault.type.name} Key Vault"
                )

        for x in content_keys:
            content_keys[content_keys.index(x)] = (x[0], x[1])

        for track in title.tracks:
            if track.encrypted:
                """Add Missing Values"""
                add_missing = ctx.obj.vaults.add_missing(title, track, commit=True)
                if not add_missing:
                    log.exit(
                        white_space
                        + " x Something went wrong while adding missing values to one of the Key Vaults"
                    )

                """ Update Values """
                update = ctx.obj.vaults.update(title, track, commit=True)
                if not update:
                    log.exit(
                        white_space
                        + " x Something went wrong updating the values in one of the Key Vaults"
                    )

    if args.dl.keys and titles.index(title) != len(titles) - 1:
        if cdm.session_id in cdm._Cdm__sessions:
            cdm.close(cdm.session_id)
        log.info_("")


def check_thread(TextTrackThread):
    if not args.dl.keys and not args.dl.list and TextTrackThread:
        if TextTrackThread.is_alive():
            if (
                not args.dl.video_only
                and not args.dl.audio_only
                and not args.dl.subs_only
            ):
                log.info_("\nWaiting for subtitles to be finished")
            TextTrackThread.join()


@click.group(
    name="dl",
    short_help="Download videos from all supported services.",
    cls=AliasedGroup,
    context_settings=dict(
        help_option_names=["-?", "-h", "--help"],
        max_content_width=116,  # max PEP8 line-width, -4 to adjust for initial indent
        default_map=getattr(config, "arguments", None),
    ),
)
@click.option(
    "-dd",
    "--download-directory",
    type=Path,
    default=None,
    help="Change the download directory.",
)
@click.option(
    "-td",
    "--temp-directory",
    type=Path,
    default=None,
    help="Change the temporary download directory.",
)
@click.option(
    "-z",
    "--zone",
    type=str,
    default=None,
    help="Profile zone to use when multiple profiles for a service is defined.",
)
@click.option(
    "-q",
    "--quality",
    callback=video_quality,
    default="1080p",
    help="Download Resolution, defaults to 1080p (FHD).",
)
@click.option(
    "-vc",
    "--video-codec",
    callback=video_codec,
    default=None,
    help="Video Codec, defaults to H.264",
)
@click.option(
    "-ac",
    "--audio-codec",
    callback=audio_codec,
    default="eac3",
    help="Audio Codec, default to EAC3",
)
@click.option(
    "-ach",
    "--audio-channels",
    callback=audio_channels,
    default="atmos",
    help="Audio Channels, default to 16/JOC",
)
@click.option(
    "-da",
    "--descriptive-audio",
    is_flag=True,
    default=False,
    help="Audio for blind or visually-impaired people, defaults to False.",
)
@click.option(
    "--external-downloader",
    type=click.Choice(["aria2c", "scatchy"], case_sensitive=False),
    default="aria2c",
    help="Prefered downloader.",
)
@click.option(
    "-d",
    "--debug",
    is_flag=True,
    default=False,
    help="Enable debugger and see all requests and responses.",
)
@click.option(
    "-sr",
    "--skip-repackage",
    is_flag=True,
    default=False,
    help="Skip repackaging files; this is not recommeneded and should only be used for testing purposes.",
)
@click.option(
    "--ignore-existing",
    "ignore_existance",
    is_flag=True,
    default=False,
    help="Skip file existance_check() save both.",
)
@click.option(
    "-r",
    "--range",
    "range",
    callback=video_range,
    default=None,
    help="Video Color Range, defaults to SDR.",
)
@click.option(
    "-le",
    "--latest-episodes",
    is_flag=True,
    default=False,
    help="Only download the most recently release episode(s)."
    "It can be possible it will download multiple episodes or an entire season if it was released on the same day.",
)
@click.option(
    "-w",
    "--wanted",
    callback=wanted_param,
    default=None,
    help="Wanted episodes, e.g. `S01-S05,S07`, `S01E01-S02E03`, `S02-S02E03`, e.t.c, defaults to all.",
)
@click.option(
    "-al",
    "--alang",
    callback=language_param,
    default="orig",
    help="Language wanted for audio tracks.",
)
@click.option(
    "-sl",
    "--slang",
    callback=language_param,
    default="all",
    help="Language wanted for subtitles.",
)
@click.option(
    "-fl",
    "--flang",
    callback=language_param,
    default="all",
    help="Language wanted for forced subtitles.",
)
@click.option(
    "--default-audio",
    callback=language_param,
    default="orig",
    help="Audio language that should be set as default when available. Multiple allowed, will use the first that matches.",
)
@click.option(
    "--default-subtitle",
    callback=language_param,
    default="orig",
    help="Subtitle language that should be set as default when available. Multiple allowed, will use the first that matches.",
)
@click.option(
    "-np",
    "--no-proxy",
    is_flag=True,
    default=False,
    help="Force disable all proxy use.",
)
@click.option(
    "-p",
    "--proxy",
    type=str,
    default=None,
    help="Proxy uri to use." "Can be provided as string or in a list.",
)
@click.option(
    "-mp",
    "--metadata-proxy",
    type=str,
    default=None,
    help="Proxy used for retrieving Metdata."
    "Name of a proxy list, country or uri itself can be used."
    "Default to proxy argument if being used.",
)
@click.option(
    "-dp",
    "--download-proxy",
    type=str,
    default=None,
    help="Proxy used for downloading content."
    "Name of a proxy list, country or uri itself can be used."
    "Default to proxy argument if being used.",
)
@click.option(
    "-ps",
    "--proxy-service",
    callback=proxy_service_param,
    default=None,
    help="Proxy service to use.",
)
@click.option(
    "-pc",
    "--proxy-country",
    type=str,
    default=None,
    help="Country which you want to connect the proxy with.",
)
@click.option(
    "-V",
    "--video-only",
    is_flag=True,
    default=False,
    help="Only download video tracks.",
)
@click.option(
    "-A",
    "--audio-only",
    is_flag=True,
    default=False,
    help="Only download audio tracks.",
)
@click.option(
    "-S",
    "--subs-only",
    is_flag=True,
    default=False,
    help="Only download subtitle tracks.",
)
@click.option(
    "-C", "--chapters-only", is_flag=True, default=False, help="Only download chapters."
)
@click.option(
    "--list",
    "list",
    type=click.Choice(["ALL", "PREFERRED", "SELECTED"], case_sensitive=False),
    default=None,
)
@click.option(
    "--cdm",
    "--content-decryption-module",
    type=str,
    default=None,
    help="Override the Cdm that will be used for decryption.",
)
@click.option(
    "--keys",
    is_flag=True,
    default=False,
    help="Skip downloading, retrieve the decryption keys (via CDM or Key Vaults) and print them.",
)
@click.option(
    "-C",
    "--cache",
    "--cached-keys",
    is_flag=True,
    default=False,
    help="Disable the use of the CDM and only retrieve decryption keys from Key Vaults. "
    "If a needed key is unable to be retrieved from any Key Vaults, the title is skipped.",
)
@click.option(
    "-nc",
    "--no-cache",
    "--no-cached-keys",
    is_flag=True,
    default=False,
    help="Disable the use of Key Vaults and only retrieve decryption keys from the CDM.",
)
@click.option(
    "--no-mux",
    is_flag=True,
    default=False,
    help="Do not mux the downloaded and decrypted tracks.",
)
@click.option(
    "--log",
    "log_path",
    type=Path,
    default=filenames.log,
    help="Log path (or filename). Path can contain the following f-string args: {name} {time}.",
)
@click.option(
    "-mp4",
    "--mux-mp4",
    is_flag=True,
    default=False,
    help="Muxing Dolby Vision in an MPEG4 container.",
)
@click.option(
    "-p2p",
    "--p2p-naming",
    is_flag=True,
    default=False,
    help="Use P2P naming in folder structure.",
)
@click.pass_context
def dl(ctx, zone, *_, **__):
    global args
    args = arguments(dl=ctx.params)

    if not args.main.help:
        if not ctx.invoked_subcommand:
            log.exit("Subcommand to invoke was not specified, cannot continue.")

        service = None
        if not args.main.title:
            service, zone, region = services.get_service_key(
                ctx.invoked_subcommand, args.main.title
            )
        else:
            service, zone, region = services.get_service_key(
                ctx.invoked_subcommand, args.main.title
            )

            zone = args.dl.zone if args.dl.zone else zone

            region = (
                ctx.args[ctx.args.index("--region") + 1]
                if [x for x in ctx.args if x == "--region"]
                else region
            )

            if not service:
                log.exit("Unable to find service")

            profile = get_profile(ctx, service, zone, region)
            service_config = get_service_config(service)

            service_cdm = config.cdm.get(service) or config.cdm.get("default")
            if service_cdm:
                service_cdm = (
                    service_cdm.replace("_", "-").replace("-L1", "").replace("-L3", "")
                )

            global cdm
            cdm = cdm_(
                cdm_device=Cdm.device(
                    config, directories, service, profile, deviceName=args.dl.cdm
                ),
                reset=True,
            ).cdm

            if profile:
                cookies = get_cookie_jar(service, profile.lower())
                credentials = get_credentials(ctx, service, profile, zone, region)
                if (
                    not cookies
                    and not credentials
                    and service not in ["Apple", "Amazon", "DPGMedia", "PcokSky"]
                ):
                    log.exit(
                        f"There are no cookies or credentials provided for service {service!r}"
                    )
            else:
                cookies = None
                credentials = None

            set_service_args(service)

            directories.downloads = args.dl.download_directory or directories.downloads
            directories.temp = args.dl.temp_directory or directories.temp

            if not args.dl.range:
                args.dl.range = (
                    config.video_range.get(service)
                    if config.video_range.get(service)
                    else config.video_range.get("default") or "SDR"
                )

            if not args.dl.video_codec:
                args.dl.video_codec = (
                    "H.264"
                    if args.dl.range == "SDR" and args.dl.quality <= 1080
                    else "H.265"
                )

            if args.dl.video_codec == "H.264" and args.dl.quality <= 1080:
                args.dl.range = "SDR"

            ctx.obj = ContextData(
                config=service_config,
                vaults=[],
                cdm=cdm,
                service_cdm=service_cdm,
                profile=profile,
                cookies=cookies,
                credentials=credentials,
            )


@dl.result_callback()
@click.pass_context
def result(ctx, service, *_, **__):
    global args  # Make sure the service arguments are also present
    args = arguments()

    def ccextractor(track):
        log.info_(" Extracting captions from stream")
        track_id = f"ccextractor-{track.id}"
        # TODO: Is it possible to determine the language of EIA-608 captions?
        cc_lang = track.language
        try:
            cc = track.ccextractor(
                track_id=track_id,
                out_path=filenames.subtitles.format(id=track_id, language_code=cc_lang),
                language=cc_lang,
                directories=directories,
                original=False,
                first=track.needs_ccextractor_first,
            )
        except EnvironmentError:
            log.warning_(" - CCExtractor not found, cannot extract captions")
        else:
            if cc:
                title.tracks.add(cc)
                log.info_(f"{clean_line} ✓ Captions extracted")
            else:
                log.info_(f"{clean_line} - No captions found")

    service_name = service.cli.name

    log.info_("PREPARING CONTENT DECRYPTION MODULE", style="title")
    Cdm.test(service, cdm, silent=False)

    log.info_("\n[title]RETRIEVING INFO FROM SERVICE[/title]")
    log.info_(f" - [#FF8C00]SERVICE[/#FF8C00]      {service_name}")
    if service_name == "DisneyPlus":
        log.info_(f" - [#FF8C00]SCENARIO[/#FF8C00]     {service.scenario}")
    elif service_name == "Netflix":
        log.info_(f" - [#FF8C00]ESN[/#FF8C00]          {service.esn}")
    log.info_(f" - [#FF8C00]TITLE_ID[/#FF8C00]     {service.title}")

    titles = Titles(as_list(service.get_titles()))
    if not titles:
        log.exit("\nCould not find the content provided")

    for title in titles:
        if title.year:
            if f"({title.year})" in title.name:
                titles.title_name = titles.title_name.replace(f" ({title.year})", "")
                title.name = title.name.replace(f" ({title.year})", "")
                title.filename = title.filename.replace(
                    f"{title.year}.{title.year}", str(title.year)
                )

    titles.order()
    wanted_titles = [title for title in titles.with_wanted(args.dl.wanted)]
    titles.print(service, getattr(service, "total_titles", None), wanted_titles)

    if args.dl.keys:
        log.info_("\n[title]COLLECTING CONTENT KEYS[/title]")

    for title in wanted_titles:
        if not os.path.exists(directories.temp):
            os.mkdir(directories.temp)

        # Change orig in alang, slang and flang to the original language
        for arg_type in (
            args.dl.alang,
            args.dl.default_audio,
            args.dl.slang,
            args.dl.default_subtitle,
            args.dl.flang,
        ):
            if any(language == "orig" for language in arg_type):
                if title.original_lang.language not in arg_type:
                    arg_type[arg_type.index("orig")] = title.original_lang.language
                else:
                    del arg_type[arg_type.index("orig")]

        for typelang in (args.dl.alang, args.dl.slang, args.dl.flang):
            for lang in typelang:
                if not lang:
                    del args.dl.alang[args.dl.alang.index(lang)]

        title.tracks.add(service.get_tracks(title))
        title.tracks.add(service.get_chapters(title))
        title.tracks.sort_videos(by_language=args.dl.alang)
        title.tracks.sort_audio(by_language=args.dl.alang)
        title.tracks.sort_subtitles()
        title.tracks.sort_chapters()
        title.tracks.remove_dupes()

        if title.tracks.videos == []:
            continue

        if getattr(args.dl, "profile_check", False):
            log.info_("\n[title]PROFILE CHECK[/title]")
            sleep(0.5)
            service.profile_check(title)
            continue

        for track in title.tracks:
            track.configure()  # Make sure all variables are correct

        all_tracks = [title.tracks.videos, title.tracks.audio, title.tracks.subtitles]

        title.tracks.select_videos()
        title.tracks.select_audio()
        title.tracks.select_subtitles()
        
        if args.dl.list:
            Tracks.list(
                title=title,
                all_tracks=all_tracks,
                selected_tracks=[
                    title.tracks.videos,
                    title.tracks.audio,
                    title.tracks.subtitles,
                ],
            )
            continue

        for track in title.tracks:
            if track.encrypted:
                if not track.get_pssh(service):
                    log.exit(f" x Could not get the PSSH from {track.type}")
                if not track.get_kid(service):
                    log.exit(f" x Could not get the KID from {track.type}")
                track.get_pssh_b64()

            if (
                isinstance(track, VideoTrack)
                and track.descriptor == track.Descriptor.M3U
                or isinstance(track, AudioTrack)
                and track.descriptor == track.Descriptor.M3U
            ):
                track.get_segments(service)

        if (
            args.dl.video_only
            or args.dl.audio_only
            or args.dl.subs_only
            or args.dl.chapters_only
        ):
            if not args.dl.video_only:
                title.tracks.videos.clear()
            if not args.dl.audio_only:
                title.tracks.audio.clear()
            if not args.dl.subs_only:
                title.tracks.subtitles.clear()
            if not args.dl.chapters_only:
                title.tracks.chapters.clear()

        if args.dl.keys:
            white_space = ""
            if title.type == Title.Types.MOVIE:
                log.info_(f"{title.name}{f' ({title.year})' if title.year else ''}")
            elif title.type == Title.Types.TV:
                log.info_(f"{title.name} S{title.season:02d}E{title.episode:02d}")
                white_space = " "
            if any(x.encrypted for x in title.tracks):
                get_content_keys(title, titles, ctx, service, service_name, white_space)
            if not any(x.encrypted for x in title.tracks):
                log.warning_(" - None of the tracks are encrypted\n")
            continue
        else:
            title.filename = title.parse_filename(service)
            if len(title.tracks.audio) == 2:
                title.filename = title.filename.replace("WEB-DL", "WEB-DL.DUAL")
            elif len(title.tracks.audio) >= 3:
                title.filename = title.filename.replace("WEB-DL", "WEB-DL.MULTI")

            if not args.dl.list:
                if titles.existance_check(args, directories, service_name, title):
                    continue

            """ Check if files in temp directory belongs to the title """
            if not args.dl.keys and not args.dl.list:
                cached = False
                title_ = (
                    (
                        f"{title.name} S{title.season:02}E{title.episode:02}"
                        if title.type == Title.Types.TV
                        else f"{title.name} ({title.year})"
                    )
                    if title.year
                    else f"{title.name}"
                )
                if (
                    title.type == Title.Types.TV_TRAILER
                    or title.type == Title.Types.MOVIE_TRAILER
                ):
                    title_ += " [Trailer]"
                if os.path.isfile(directories.temp / "cache.txt"):
                    with open(directories.temp / "cache.txt", "r+") as cache_file:
                        for line in cache_file:
                            if "Title" in line:
                                cached = True if title_ in line else False
                            if "Resolution" in line and title.tracks.videos and cached:
                                cached = True if title.resolution in line else False

                        if not cached:
                            shutil.rmtree(directories.temp, ignore_errors=True)
                            if not os.path.exists(directories.temp):
                                os.mkdir(directories.temp)
                            with open(
                                directories.temp / "cache.txt", "w+"
                            ) as cache_file:
                                cache_file.write(f"Title: {title_}")
                                if title.tracks.videos:
                                    cache_file.write(
                                        f"\nResolution: {title.resolution}"
                                    )
                else:
                    with open(directories.temp / "cache.txt", "w+") as cache_file:
                        cache_file.write(f"Title: {title_}")
                        if title.tracks.videos:
                            cache_file.write(f"\nResolution: {title.resolution}")

            """Downloading TextTracks in Background if Available"""
            TextTrackThread = None
            if not title.tracks.subtitles:
                if (
                    args.dl.subs_only
                    or not args.dl.subs_only
                    and (
                        title.tracks.videos
                        and not args.dl.video_only
                        or title.tracks.audio
                        and not args.dl.audio_only
                    )
                ):
                    log.warning_(
                        " - No subtitles available.".rstrip("\r"),
                    )
            else:
                TextTrackThread = Thread(
                    target=title.tracks.subtitles[0].threading,
                    args=(title, service, directories, ctx),
                )
                TextTrackThread.start()
                sleep(0.1)

            """Downloading Video and Audio Tracks"""
            for track in title.tracks:
                downloaded = os.path.isfile(
                    f"{track.location}.mp4"
                ) and not os.path.isfile(f"{track.location}.mp4.aria2")
                continue_ = (
                    not downloaded
                    and os.path.isdir(directories.temp / "segments")
                    or os.path.isfile(f"{track.location}.mp4.aria2")
                    or os.path.isfile(f"{track.location}_segments")
                )

                if not isinstance(track, TextTrack):
                    log.info_(
                        f" ✓ {track.type} Already Downloaded {track.map}"
                        if downloaded and not continue_
                        else f" + Continue Downloading {track.type} {track.map}"
                        if not downloaded and continue_
                        else f" + Downloading {track.type} {track.map}"
                    )

                    if not downloaded:
                        track.download(
                            title,
                            ctx,
                            headers=service.session.headers,
                        )

                    if isinstance(track, VideoTrack) and track.needs_ccextractor_first:
                        ccextractor(track)

            # Just to make sure Subtitle Already Downloaded
            # message pops at the right moment
            sleep(0.1)

            """Decrypting Encrypted Track(s)"""
            for file in os.listdir(directories.temp):
                if "packager-tempfile" in file:
                    os.remove(directories.temp / file)
                    exit()
            if (
                (title.tracks.videos or title.tracks.audio)
                and not args.dl.keys
                and not args.dl.list
            ):
                extension = "mp4"
                log.info_("\nDECRYPTING TRACKS", style="title")
                if any(track.encrypted for track in title.tracks) and any(
                    not os.path.isfile(
                        f"{track.location}.{extension}".replace("enc", "dec")
                    )
                    for track in title.tracks
                    if track.encrypted
                ):
                    get_content_keys(title, titles, ctx, service, service_name)
                elif (
                    not any(track.encrypted for track in title.tracks)
                    and not args.dl.audio_only
                ):
                    log.warning_(" - None of the tracks are encrypted")

                for track in title.tracks:
                    if track.encrypted:
                        enc_file_input = f"{track.location}.{extension}"
                        dec_file_output = enc_file_input.replace("enc", "dec")

                        if os.path.isfile(dec_file_output):
                            log.info_(f" ✓ {track.type} Already Decrypted {track.map}")
                            track.swap(dec_file_output)
                        else:
                            if not track.key:
                                log.exit(
                                    f" x Encrypted {track.type} does not have any key for decryption"
                                )

                            log.info_(f" + Decrypting {track.type} {track.map}\n")
                            cdm.decrypt(
                                session_id=cdm.session_id,
                                track=track,
                                input_file=enc_file_input,
                                output_file=dec_file_output,
                                temp_dir=directories.temp,
                            )
                            track.swap(dec_file_output)

                    if (
                        not track.encrypted
                        and not isinstance(track, TextTrack)
                        and not isinstance(track, MenuTrack)
                    ):
                        log.info_(f" - {track.type} Is Not Encrypted {track.map}")
                        track.swap(f"{track.location}.{extension}")

                    """Repackage Video and Audio Tracks"""
                    if not args.dl.skip_repackage and not (
                        track.dv if isinstance(track, VideoTrack) else False
                    ):
                        if isinstance(track, VideoTrack) or isinstance(
                            track, AudioTrack
                        ):
                            repackaged = os.path.isfile(
                                f"{str(track.location).replace('.mp4', '')}_fixed.{extension}"
                            )
                            if repackaged:
                                track.swap(
                                    f"{str(track.location).replace('.mp4', '')}_fixed.{extension}"
                                )
                            else:
                                track.repackage()
                                log.info_(f"{clean_line}   ✓ {track.type} Repackaged")
                                track.swap(
                                    f"{str(track.location).replace('.mp4', '')}_fixed.{extension}"
                                )

                    if isinstance(track, VideoTrack) and track.needs_ccextractor:
                        ccextractor(track)

                if (
                    getattr(cdm, "session_id", None)
                    and cdm.session_id in cdm._Cdm__sessions
                    and cdm._Cdm__sessions[cdm.session_id].opened_at
                ):
                    cdm.close(cdm.session_id)

            if not list(title.tracks):
                continue

            """Mux all tracks to a single MPEG4 or MKV container
               and inject Dolby Vision metadata if needed"""
            title_year = f" ({title.year})" if len(str(title.year)) == 4 else ""
            contentFolder = f"{Title.normalize_foldername(title.name)}{title_year}"
            contentFolder += (
                f" [imdb-{title.imdb_id}]"
                if title.imdb_id
                else f" [tmdb-{title.tmdb_id}]"
                if title.tmdb_id
                else f" [tvdb-{title.tvdb_id}]"
                if title.tvdb_id
                else ""
            )

            final_file_path = directories.downloads
            service_name_ = service_name.lower().replace("prime video", "amazon")
            if (
                service_name_ not in str(final_file_path)
                and not args.dl.download_directory
            ):
                final_file_path = final_file_path / service_name_
                final_file_path = (
                    final_file_path / "movies"
                    if title.type in (Title.Types.MOVIE, Title.Types.MOVIE_TRAILER)
                    else final_file_path / "tv"
                )
                final_file_path = final_file_path / contentFolder

            if (
                not final_file_path.name.endswith(contentFolder)
                and title.name not in final_file_path.name
            ):
                final_file_path = final_file_path / contentFolder

            if title.type == Title.Types.TV:
                final_file_path = (
                    final_file_path / f"Season {title.season}"
                    if not args.dl.p2p_naming
                    else final_file_path / "REPLACE_SEASONFOLDER"
                )

            if args.dl.no_mux:
                check_thread(TextTrackThread)
                if title.tracks.chapters:
                    chapters_loc = Path(
                        str(filenames.chapters).format(filename=title.filename)
                    )
                    title.tracks.export_chapters(chapters_loc)
                for track in title.tracks:
                    filename = title.parse_filename(
                        media_info=MediaInfo.parse(track.locate())
                    )
                    extension = (
                        "srt"
                        if isinstance(track, TextTrack)
                        else track.locate().suffix[1:]
                    )

                    if args.dl.p2p_naming and title.type == Title.Types.TV:
                        final_file_path = Path(
                            str(final_file_path)
                            .replace(
                                "REPLACE_SEASONFOLDER",
                                filename.replace(f"E{title.episode:02d}", "").replace(
                                    Title.normalize_foldername(
                                        title.episode_name
                                    ).replace(" ", "."),
                                    "",
                                )
                                if title.season
                                else filename.replace(
                                    f"S{title.season:2d}E{title.episode:02d}",
                                    "Specials",
                                ).replace(
                                    Title.normalize_foldername(
                                        title.episode_name
                                    ).replace(" ", "."),
                                    "",
                                ),
                            )
                            .replace("..", ".")
                        )

                    if args.dl.ignore_existance:
                        filename = f"[DUPE] {filename}"

                    final_file_path.mkdir(parents=True, exist_ok=True)
                    track.move(
                        final_file_path
                        / (
                            "{}.{}.{}".format(
                                filename, track.language._str_tag, extension
                            )
                        )
                    )
            else:
                if len(title.tracks.videos) == 2 and not args.dl.mux_mp4:
                    Tracks.DV_INJECTION(title.tracks.videos)

                check_thread(TextTrackThread)

                log.info_("\nMUXING TRACKS\n", style="title")
                extension = (
                    "mka"
                    if args.dl.audio_only
                    and not args.dl.video_only
                    and not args.dl.subs_only
                    else "mks"
                    if args.dl.subs_only
                    and not args.dl.video_only
                    and not args.dl.audio_only
                    else "mp4"
                    if len(title.tracks.videos) == 1
                    and title.tracks.videos[0].dv
                    and args.dl.mux_mp4
                    else "mkv"
                )

                mux_location = directories.temp / f"{title.filename}.muxed.{extension}"
                if os.path.isfile(mux_location):
                    log.info_(f"{clean_line} ✓ Tracks Already Muxed, Finalizing...")
                else:
                    muxing = (
                        title.tracks.mux_mp4(title, directories)
                        if len(title.tracks.videos) == 1
                        and title.tracks.videos[0].dv
                        and args.dl.mux_mp4
                        else title.tracks.mux(service, title, directories, extension)
                    )

                    if muxing and muxing.returncode:
                        log.exit(f"{clean_line} x Failed")
                        if os.path.isfile(mux_location):
                            os.remove(mux_location)
                        exit()
                    else:
                        log.info_(f"{clean_line} ✓ Succesfully Muxed")

                media_info = MediaInfo.parse(mux_location)
                filename = title.parse_filename(media_info=media_info).replace(
                    ":", " -"
                )
                if len(title.tracks.audio) == 2:
                    filename = filename.replace("WEB-DL", "WEB-DL.DUAL")
                elif len(title.tracks.audio) >= 3:
                    filename = filename.replace("WEB-DL", "WEB-DL.MULTI")

                if args.dl.p2p_naming and title.type == Title.Types.TV:
                    final_file_path = Path(
                        str(final_file_path)
                        .replace(
                            "REPLACE_SEASONFOLDER",
                            filename.replace(f"E{title.episode:02d}", "").replace(
                                Title.normalize_foldername(title.episode_name).replace(
                                    " ", "."
                                ),
                                "",
                            )
                            if title.season
                            else filename.replace(
                                f"S{title.season:2d}E{title.episode:02d}", "Specials"
                            ).replace(
                                Title.normalize_foldername(title.episode_name).replace(
                                    " ", "."
                                ),
                                "",
                            ),
                        )
                        .replace("..", ".")
                    )

                if args.dl.ignore_existance:
                    filename = f"[DUPE] {filename}"

                final_file_path.mkdir(parents=True, exist_ok=True)
                shutil.move(
                    mux_location,
                    final_file_path / f"{filename}.{extension}",
                )

            if os.path.isfile(final_file_path / f"{filename}.{extension}"):
                shutil.rmtree(directories.temp, ignore_errors=True)

    if args.main.links:
        raise NextTitle


def load_services() -> None:
    for service in services.__dict__.values():
        if callable(getattr(service, "cli", None)):
            dl.add_command(service.cli)


load_services()
