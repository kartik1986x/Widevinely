from __future__ import annotations

import requests
import asyncio
import httpx
import base64
import binascii
import logging
import math
import re
import json
import os
import m3u8
import pysrt
import sys
import unicodedata
import shutil
import subprocess

from enum import Enum
from uuid import UUID
from pathlib import Path
from pymediainfo import MediaInfo
from typing import Any, Iterator, Optional, Sequence, TypeVar, Union
from sys import platform
from construct import Container
from langcodes import Language
from rich.tree import Tree

from pywidevinely.utils.protos.license_protocol_pb2 import WidevinePsshData
from pywidevinely import Cdm
from widevinely import config
from widevinely.constants import TERRITORY_MAP
from widevinely.utils.exceptions import *
from widevinely.utils import (
    FPS,
    logger,
    clean_line,
    get_boxes,
    get_closest_match,
    is_close_match,
)
from widevinely.utils.collections import as_list
from widevinely.utils.io import scatchy, aria2c, saldl
from widevinely.utils.subprocess import ffprobe
from widevinely.utils.globals import arguments
from pywidevinely import PSSH

log = logger.getLogger("tracks")

# For use in signatures of functions which take one specific type of track at a time
# (it can't be a list that contains e.g. both VideoTrack and AudioTrack)
TrackT = TypeVar("TrackT", bound="Track")

# For general use in lists that can contain mixed types of tracks.
# list[Track] won't work because list is invariant.
AnyTrack = Union["VideoTrack", "AudioTrack", "TextTrack"]


class Track:
    class Descriptor(Enum):
        URL = 1  # Direct URL, nothing fancy
        M3U = 2  # https://en.wikipedia.org/wiki/M3U (and M3U8)
        MPD = 3  # https://en.wikipedia.org/wiki/Dynamic_Adaptive_Streaming_over_HTTP

    def __init__(
        self,
        id_: str,
        source: str,
        url: Union[str, list[str]],
        codec: Optional[str],
        language: Union[Language, str],
        is_original_lang: bool = False,
        descriptor: Descriptor = Descriptor.URL,
        imax_enhanced: bool = False,
        original_aspect_ratio: bool = False,
        encrypted: bool = False,
        pssh: Optional[Container] = None,
        kid: Optional[str] = None,
        key: Optional[str] = None,
        extra: Optional[Any] = None,
    ) -> None:
        self.id = id_
        self.source = source
        self.url = url
        # required basic metadata
        self.codec = codec
        try:
            self.language = Language.get(language)
        except AttributeError:
            Language.get("nl") if source == "VL" else Language.get("en")
        self.is_original_lang = bool(is_original_lang)
        # optional io metadata
        self.descriptor = descriptor
        self.imax_enhanced = imax_enhanced
        self.original_aspect_ratio = original_aspect_ratio
        # decryption
        self.encrypted = bool(encrypted)
        self.pssh: Container = pssh
        self.kid = kid
        self.key = key
        # extra data
        self.extra: Any = extra or {}  # allow anything for extra, but default to a dict

        # should only be set internally
        self.type = type(self).__name__
        self.variables = {}

        global args__
        args__ = arguments()

    def __repr__(self) -> str:
        return "{name}({items})".format(
            name=self.__class__.__name__,
            items=", ".join([f"{k}={repr(v)}" for k, v in self.__dict__.items()]),
        )

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Track) and self.id == other.id

    def get_track_name(self):
        """Return the base Track Name. This may be enhanced in sub-classes."""
        if (self.language.language or "").lower() == (
            self.language.territory or ""
        ).lower() and self.language.territory not in TERRITORY_MAP:
            self.language.territory = None  # e.g. de-DE
        if self.language.territory == "US":
            self.language.territory = None
        language = self.language.simplify_script()
        extra_parts = []
        if language.script is not None:
            extra_parts.append(language.script_name())
        if language.territory is not None:
            territory = language.territory_name()
            extra_parts.append(TERRITORY_MAP.get(language.territory, territory))
        return ", ".join(extra_parts) or None

    def get_data_chunk(self, service) -> Optional[bytes]:
        """
        Get the Track's Initial Segment Data Stream.
        If the Track URL is not detected to be an init segment, it will download
        up to the first 20,000 (20KB) bytes only.
        """
        url = None
        is_init_stream = False

        if self.descriptor == self.Descriptor.M3U:
            master = m3u8.loads(
                service.session.get(as_list(self.url)[0]).text, uri=self.url
            )
            for segment in master.segments:
                if not segment.init_section:
                    continue
                if self.source == "DSNP" and re.match(
                    r"^[a-zA-Z0-9]{4}-(BUMPER|DUB_CARD)/", segment.init_section.uri
                ):
                    continue
                url = (
                    ""
                    if re.match("^https?://", segment.init_section.uri)
                    else segment.init_section.base_uri
                )
                url += segment.init_section.uri
                is_init_stream = True
                break

        if not url:
            url = self.url

        if isinstance(url, list):
            url = url[0]
            is_init_stream = True

        if is_init_stream:
            return service.session.get(url).content

        # Assuming 20k bytes would be enough to contain the PSSH/KID
        return service.session.get(url, headers={"Range": "bytes=0-20000"}).content

    def get_pssh(self, service):
        """
        Get the PSSH of the track.

        Parameters:
            session: HTTPX Session, best to provide one if cookies/headers/proxies are needed.

        Returns:
            True if PSSH is now available, False otherwise.
            PSSH will be stored in Track.pssh automatically.
        """
        if self.pssh or not self.encrypted:
            return True

        if self.descriptor == self.Descriptor.M3U:
            master = m3u8.loads(
                service.session.get(as_list(self.url)[0]).text, uri=self.url
            )

            for x in master.session_keys or master.keys:
                if x and x.keyformat.lower() == Cdm.urn:
                    self.pssh = PSSH(base64.b64decode(x.uri.split(",")[-1]))
                    break  # Prevent overwriting if there is more than one match

        if not getattr(self, "pssh", None):
            self.pssh = get_boxes(self.get_data_chunk(service), b"pssh")

        if self.pssh.system_id == PSSH.SystemId.Widevine:
            return True

        if self.pssh.system_id == PSSH.SystemId.PlayReady:
            PSSH.to_widevine(self.pssh)
            return True

        return False

    def get_kid(self, service) -> bool:
        """
        Get the KID (encryption key id) of the Track.
        The KID corresponds to the Encrypted segments of an encrypted Track.

        Parameters:
            session: HTTPX Session, best to provide one if cookies/headers/proxies are needed.

        Returns:
            True if KID is now available, False otherwise.
            KID will be stored in Track.kid automatically.
        """
        if self.kid or not self.encrypted:
            return True

        if self.pssh.system_id == Cdm.uuid and service.cli.name not in [
            "DisneyPlus",
            "HBOMax",
        ]:
            # Note: assumes only the first KID of a list is wanted
            if getattr(self.pssh, "key_ids", None):
                kid = self.pssh.key_ids[0].hex
                if kid != "00" * 16:
                    self.kid = kid
                    return True
            cenc_header = WidevinePsshData()
            cenc_header.ParseFromString(self.pssh.init_data)
            if getattr(cenc_header, "key_ids", None):
                kid = binascii.hexlify(cenc_header.key_ids[0]).decode()
                if kid != "00" * 16:
                    self.kid = kid
                    return True

        data = self.get_data_chunk(service)

        if b"Access Denied" in data or b"Forbidden" in data:
            raise VPN_PROXY_DETECTED
        if b"Error" in data:
            log.exit("\nCould not get data chunk.")

        if data:
            # try get via ffprobe, needed for non mp4 data e.g. WEBM from Google Play
            probe = ffprobe(data)
            if probe:
                kid = (
                    (probe.get("streams") or [{}])[0].get("tags", {}).get("enc_key_id")
                )
                if kid:
                    kid = binascii.hexlify(base64.b64decode(kid)).decode()
                    if kid != "00" * 16:
                        self.kid = kid
                        return True

            # try to get KID from tenc box
            kid = get_boxes(data, b"tenc").tenc_key_ID
            if kid != "00" * 16:
                self.kid = kid
                return True

        return False

    def get_pssh_b64(self):
        if self.source == "MA":  # Wants contentId appended to the init_data
            self.pssh = PSSH.new(
                system_id=PSSH.SystemId.Widevine,
                key_ids=[UUID(self.kid)],
                version=self.pssh.version,
                flags=self.pssh.flags,
            )
            self.pssh.init_data = (
                b"\x08\x01"
                + self.pssh.init_data
                + b'"='
                + bytes(self.contentId.encode("UTF-8"))
            )
            self.kid = self.kid.replace("-", "")

        if self.pssh_b64 or not self.encrypted:
            return

        self.pssh_b64 = str(self.pssh)

    def get_segments(self, service):
        master = m3u8.loads(
            service.session.get(
                as_list(self.url)[0],
            ).text,
            uri=as_list(self.url)[0],
        )

        # Keys may be [] or [None] if unencrypted
        if any(master.keys + master.session_keys):
            self.encrypted = True
            self.get_kid(service)
            self.get_pssh(service)

        durations = []
        duration = 0
        for segment in master.segments:
            if segment.discontinuity:
                durations.append(duration)
                duration = 0
            duration += segment.duration
        durations.append(duration)
        largest_continuity = durations.index(max(durations))

        discontinuity = 0
        has_init = False
        segments = []
        for segment in master.segments:
            if segment.discontinuity:
                discontinuity += 1
                has_init = False
            if self.source == "DSNP":
                if (
                    re.search(
                        r"[a-zA-Z0-9]{4}-(BUMPER)/",
                        segment.uri
                        + (segment.init_section.uri if segment.init_section else ""),
                    )
                    and not service.bumper
                ):
                    continue
                if (
                    re.search(
                        r"[a-zA-Z0-9]{4}-(DUB_CARD)/",
                        segment.uri
                        + (segment.init_section.uri if segment.init_section else ""),
                    )
                    and not service.dub_card
                ):
                    continue
            if self.source in ["ATVP", "iT"] and discontinuity != largest_continuity:
                # the amount of pre and post-roll sections change all the time
                # only way to know which section to get is by getting the largest
                continue
            if segment.init_section and not has_init:
                segments.append(
                    (
                        ""
                        if re.match("^https?://", segment.init_section.uri)
                        else segment.init_section.base_uri
                    )
                    + segment.init_section.uri
                )
                has_init = True
            segments.append(
                ("" if re.match("^https?://", segment.uri) else segment.base_uri)
                + segment.uri
            )

        if not segments and type(self.url) == list:
            segments = self.url

        if "HDR10Plus" in segments[0]:
            self.hdr10plus = True
            self.hdr10 = False
            self.dv = False
        elif "HDR10" in segments[0]:
            self.hdr10plus = False
            self.hdr10 = True
            self.dv = False
        elif "_dovi_" in segments[0]:
            self.hdr10plus = False
            self.hdr10 = False
            self.dv = True

        self.url = segments

    def download(self, title=None, ctx=None, headers=None):
        """
        Download the Track and apply any necessary post-edits like Subtitle conversion.

        Parameters:
            headers: Headers to use when downloading.
            proxy: Proxy to use when downloading.

        Returns:
            Where the file was saved, as a Path object.
        """
        if os.path.isfile(self.location.parent):
            ValueError
            log.exit("Path must be to a directory and not a file")

        try:
            httpx.Client(proxies={"all://": args__.dl.proxy["download"]}).get(
                "https://ipinfo.io/json"
            ).json()
        except Exception:
            raise ProxyConnectionError(
                type_="download", uri=args__.dl.proxy["download"]
            )

        os.makedirs(self.location.parent, exist_ok=True)
        save_path = str(self.location)
        save_path += (
            ".dash"
            if type(self.url) == list
            and (
                ".dash" in self.url[0] or ".mp4" in self.url[0] or ".m4s" in self.url[1]
            )
            and isinstance(self, TextTrack)
            else ".mp4"
        )

        if self.source == "CORE":
            asyncio.run(
                saldl(
                    self.url,
                    save_path,
                    headers,
                )
            )
        else:
            if args__.dl.external_downloader == "scatchy":
                scatchy(
                    title,
                    ctx,
                    self.url,
                    save_path,
                    headers,
                )
            else:
                aria2c(
                    title,
                    self.url,
                    save_path,
                    headers,
                )
        try:
            if os.stat(save_path).st_size <= 3:  # Empty UTF-8 BOM == 3 bytes
                log.exit(f" x Download failed, {save_path!r} is empty")
        except FileNotFoundError:
            pass

        return save_path

    def delete(self):
        if self.location:
            self.location.unlink()
            self.location = None

    def repackage(self):
        if not os.path.isfile(self.location):
            log.info_(
                f"   x {self.type} not found for repackaging".rstrip("\n"),
                style="error",
            )
            exit()

        log.info_(f"   + Repackaging {self.type}")
        subprocess.run(
            [
                "ffmpeg",
                "-hide_banner",
                "-y",
                "-loglevel",
                "panic",
                "-i",
                str(self.location),
                # Following are very important!
                "-map_metadata",
                "-1",  # don't transfer metadata to output file
                "-fflags",
                "bitexact",  # only have minimal tag data, reproducible mux
                "-codec",
                "copy",
                f"{str(self.location).replace('.mp4', '')}_fixed.mp4",
            ],
        )

    def locate(self):
        return self.location

    def move(self, target):
        if not self.location:
            return False
        target = Path(target)
        ok = Path(shutil.move(self.location, target)).resolve() == target.resolve()
        if ok:
            self.location = target
        return ok

    def swap(self, target):
        target = Path(target)
        if not target.exists():
            return False
        self.location = target
        return True


class VideoTrack(Track):
    def __init__(
        self,
        *args: Any,
        duration,
        bitrate,
        width,
        height,
        profile="",
        fps=None,
        hdr10=False,
        hdr10plus=False,
        hlg=False,
        dv=False,
        pssh=None,
        pssh_b64=None,
        fallback_pssh=None,
        needs_ccextractor=False,
        needs_ccextractor_first=False,
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        # required
        self.duration = duration
        self.bitrate = int(math.ceil(float(bitrate))) if bitrate else None
        self.width = int(width)
        self.height = int(height)
        # optional
        self.fps = FPS.parse(str(fps)) if fps else None
        self.hdr10 = bool(hdr10)
        self.hdr10plus = bool(hdr10plus)
        self.hlg = bool(hlg)
        self.dv = bool(dv)
        self.pssh = pssh
        self.pssh_b64 = pssh_b64
        self.fallback_pssh = fallback_pssh
        self.profile = profile
        self.needs_ccextractor = needs_ccextractor
        self.needs_ccextractor_first = needs_ccextractor_first
        self.configure()

    def configure(self):
        from widevinely.config import directories  # Due circular import error
        from widevinely.utils.click import video_codec

        if self.source == "AMZN":
            self.bitrate = self.calculate_bitrate()

        self.resolution = (
            2160
            if self.width >= 3840 or self.height > 1440
            else 1440
            if self.width >= 2560 or self.width > 1920 and self.height < 1440
            else 1080
            if self.width == 1920
            or self.height == 1080
            or self.width >= 1500
            or self.height >= 900
            else 720
            if self.width == 1280
            or self.height == 720
            or self.width < 1500
            and self.width >= 1100
            or self.height < 900
            and self.height >= 700
            else 576
            if self.height == 576
            else 540
            if self.height <= 960 and self.height > 720 and self.width >= 408
            else 480
            if self.height == 640 or self.height <= 854 and self.width >= 480
            else 360
            if self.height <= 640 and self.height <= 360 and self.height > 240
            else 240
            if self.height <= 360 and self.height <= 240
            else "unknown"
        )

        self.variables["range"] = (
            "HDR10+"
            if self.hdr10plus or "HDR10plus" in self.url
            else "HDR10"
            if self.hdr10
            else "DV"
            if self.dv
            else "HLG"
            if self.hlg
            else "SDR"
        )

        try:
            self.variables["codec"] = video_codec(value=self.codec)
        except AttributeError:
            self.variables["codec"] = None

        if self.variables.get("profile"):
            self.profile = self.variables["profile"]

        self.map = f"[[bold #FF8C00]{self.resolution}p, {self.variables['codec']} {self.variables['range']}"
        self.map += (
            f" ({self.profile})[/bold #FF8C00]]" if self.profile else "[/bold #FF8C00]]"
        )

        self.location = Path(
            directories.temp
            / "{type}_{id}_{enc}".format(
                type=self.type,
                id=f"{self.variables['codec']}_{self.variables['range']}",
                enc="enc" if self.encrypted else "dec",
            ).replace("16/JOC", "ATMOS")
        )

    def calculate_bitrate(self):
        size = requests.head(self.url).headers.get("content-length")
        duration = int(float(self.duration))
        return int(math.ceil(float((int(size)) / duration * 8)))

    def __str__(self) -> str:
        fps = f"{self.fps:.3f}" if self.fps else "Unknown"
        return " | ".join(
            [
                "VID",
                f"[{self.codec}, {'HDR10' if self.hdr10 else 'HLG' if self.hlg else 'DV' if self.dv else 'SDR'}]",
                f"{self.width}x{self.height} @ {self.bitrate // 1000 if self.bitrate else '?'} kb/s, {fps} FPS",
            ]
        )

    def ccextractor(
        self, track_id, out_path, language, directories, original=False, first=False
    ):
        """Return a TextTrack object representing CC track extracted by CCExtractor."""
        location = (
            directories.temp
            / f"VideoTrack_{self.variables['codec'].replace('.', '')}_{self.variables['range']}_{'enc' if first else 'dec_fixed'}.mp4"
        )
        if not location:
            log.exit(
                " x We need to download the VideoTrack first before using CCExtractor."
            )

        executable = shutil.which("ccextractor") or shutil.which("ccextractorwin")
        if not executable:
            log.exit(" x CCExtractor executable could not be found")

        p = subprocess.Popen(
            [
                executable,
                "-quiet",
                "-trim",
                "-noru",
                "-ru1",
                Path(location),
                "-o",
                out_path,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        returncode = p.wait()
        if returncode and returncode != 10:
            log.exit(f" x CCExtractor exited with return code {returncode}")

        if os.path.exists(out_path):
            if os.stat(out_path).st_size <= 3:
                # An empty UTF-8 file with BOM is 3 bytes.
                # If the subtitle file is empty, mkvmerge will fail to mux.
                os.unlink(out_path)
                return None
            cc_track = TextTrack(
                id_=track_id,
                source=self.source,
                url="",  # doesn't need to be downloaded
                codec="srt",
                language=language,
                is_original_lang=original,  # TODO: Figure out if this is the original title language
                cc=True,
            )
            cc_track._location = out_path
            return cc_track

        return None


class AudioTrack(Track):
    def __init__(
        self,
        *args: Any,
        bitrate,
        channels=None,
        atmos=False,
        profile="",
        descriptive=False,
        pssh=None,
        pssh_b64=None,
        fallback_pssh=None,
        **kwargs: Any,
    ):
        super().__init__(*args, **kwargs)
        # required
        self.bitrate = int(math.ceil(float(bitrate))) if bitrate else None
        self.channels = self.parse_channels(channels) if channels else None
        # optional
        self.profile = profile
        self.atmos = bool(atmos)
        self.descriptive = bool(descriptive)
        self.pssh = pssh
        self.pssh_b64 = pssh_b64
        self.fallback_pssh = fallback_pssh
        self.configure()

    def configure(self):
        from widevinely.config import directories  # Otherwise CircularImportError
        from widevinely.utils.click import audio_codec

        try:
            self.variables["codec"] = audio_codec(value=self.codec)
        except AttributeError:
            self.variables["codec"] = None

        if self.variables.get("profile"):
            self.profile = self.variables["profile"]

        raw_language = Language.make(self.language.language).display_name().title()

        if self.source in [
            "ATVP",
            "iT",
        ]:  # AFAIK the only services that encrypt their audio in a m3u8 manifest
            self.encrypted = True

        if self.language._str_tag == "nl-NL":
            raw_language = "Dutch"
        if self.language._str_tag == "nl-BE":
            raw_language = "Flemish"

        self.channels = "16/JOC" if self.atmos else self.channels

        self.map = f"[[bold #FF8C00]{raw_language}{' (Original)' if self.is_original_lang else ''}, {self.variables.get('codec') or self.codec} {'5.1' if self.channels in ['16/JOC', '5.1'] else '2.0' if self.channels == '2.0' else ''}"
        self.map += (
            f" (Dolby Atmos{f', {self.profile}' if self.profile else ''})[/bold #FF8C00]]"
            if self.atmos or self.channels == "16/JOC"
            else f"{f' ({self.profile})' if self.profile else ''}[/bold #FF8C00]]"
        )

        self.location = Path(
            directories.temp
            / "{type}_{id}_{enc}".format(
                type=self.type,
                id=f"{str(self.language)}_{self.variables['codec']}_{self.channels}",
                enc="enc" if self.encrypted else "dec",
            ).replace("16/JOC", "ATMOS")
        )

    @staticmethod
    def parse_channels(channels: Union[str, float]) -> str:
        """
        Converts a string to a float-like string which represents audio channels.
        It does not handle values that are incorrect/out of bounds or e.g. 6.0->5.1, as that
        isn't what this is intended for.
        E.g. "3" -> "3.0", "2.1" -> "2.1", ".1" -> "0.1".
        """
        # TODO: Support all possible DASH channel configurations (https://datatracker.ietf.org/doc/html/rfc8216)
        if channels == "A000":
            return "2.0"
        if channels == "F801":
            return "5.1"

        if str(channels).isdigit():
            # This is to avoid incorrectly transforming channels=6 to 6.0, for example
            if "6" in channels:
                return "5.1"
            elif "2" in channels:
                return "2.0"

        try:
            return str(float(channels))
        except ValueError:
            return str(channels)

    def get_track_name(self) -> Optional[str]:
        """Return the base Track Name."""
        track_name = super().get_track_name() or ""
        flag = self.descriptive and "Descriptive"
        if flag:
            if track_name:
                flag = f" ({flag})"
            track_name += flag
        return track_name or None

    def __str__(self):
        return " | ".join(
            [
                x
                for x in [
                    "AUD",
                    f"[{self.codec}]",
                    f"{self.channels}" if self.channels else None,
                    f"{self.bitrate // 1000 if self.bitrate else '?'} kb/s",
                    f"{self.language}",
                    " ".join(
                        [
                            self.get_track_name() or "",
                            "[Original]" if self.is_original_lang else "",
                        ]
                    ).strip(),
                ]
                if x
            ]
        )


class TextTrack(Track):
    def __init__(self, *args: Any, cc=False, sdh=False, forced=False, **kwargs: Any):
        """
        Information on Subtitle Types:
            https://bit.ly/2Oe4fLC (3PlayMedia Blog on SUB vs CC vs SDH).
            However, I wouldn't pay much attention to the claims about SDH needing to
            be in the original source language. It's logically not true.

            CC == Closed Captions. Source: Basically every site.
            SDH = Subtitles for the Deaf or Hard-of-Hearing. Source: Basically every site.
            HOH = Exact same as SDH. Is a term used in the UK. Source: https://bit.ly/2PGJatz (ICO UK)

            More in-depth information, examples, and stuff to look for can be found in the Parameter
            explanation list below.

        Parameters:
            cc: Closed Caption.
                - Intended as if you couldn't hear the audio at all.
                - Can have Sound as well as Dialogue, but doesn't have to.
                - Original source would be from an EIA-CC encoded stream. Typically all
                  upper-case characters.
                Indicators of it being CC without knowing original source:
                  - Extracted with CCExtractor, or
                  - >>> (or similar) being used at the start of some or all lines, or
                  - All text is uppercase or at least the majority, or
                  - Subtitles are Scrolling-text style (one line appears, oldest line
                    then disappears).
                Just because you downloaded it as a SRT or VTT or such, doesn't mean it
                 isn't from an EIA-CC stream. And I wouldn't take the streaming services
                 (CC) as gospel either as they tend to get it wrong too.
            sdh: Deaf or Hard-of-Hearing. Also known as HOH in the UK (EU?).
                 - Intended as if you couldn't hear the audio at all.
                 - MUST have Sound as well as Dialogue to be considered SDH.
                 - It has no "syntax" or "format" but is not transmitted using archaic
                   forms like EIA-CC streams, would be intended for transmission via
                   SubRip (SRT), WebVTT (VTT), TTML, etc.
                 If you can see important audio/sound transcriptions and not just dialogue
                  and it doesn't have the indicators of CC, then it's most likely SDH.
                 If it doesn't have important audio/sounds transcriptions it might just be
                  regular subtitling (you wouldn't mark as CC or SDH). This would be the
                  case for most translation subtitles. Like Anime for example.
            forced: Typically used if there's important information at some point in time
                     like watching Dubbed content and an important Sign or Letter is shown
                     or someone talking in a different language.
                    Forced tracks are recommended by the Matroska Spec to be played if
                     the player's current playback audio language matches a subtitle
                     marked as "forced".
                    However, that doesn't mean every player works like this but there is
                     no other way to reliably work with Forced subtitles where multiple
                     forced subtitles may be in the output file. Just know what to expect
                     with "forced" subtitles.
        """
        super().__init__(*args, **kwargs)
        self.cc = bool(cc)
        self.sdh = bool(sdh)
        if self.cc and self.sdh:
            log.exit(" x A TextTrack cannot be both CC and SDH.")
        self.forced = bool(forced)
        if (self.cc or self.sdh) and self.forced:
            log.exit(" x A TextTrack cannot be CC/SDH as well as Forced.")

        if len(self.language._str_tag) > 2 and "-" not in self.language._str_tag:
            new_tag = (
                f"{self.language._str_tag[:2]}-{self.language._str_tag[-2:].upper()}"
            )
            self.id = self.id.replace(self.language._str_tag, new_tag)
            self.language = Language.get(new_tag)

        self.configure()

    def configure(self):
        from widevinely.config import directories  # Due circular import error

        self.variables["flag"] = (
            "SDH" if self.sdh else "Forced" if self.forced else "CC" if self.cc else ""
        )

        self.map = f"[[bold #FF8C00]{self.language.display_name()}"
        self.map += (
            f" ({self.variables['flag']}), {self.codec.upper()}[/bold #FF8C00]]"
            if self.variables["flag"]
            else f", {self.codec.upper()}[/bold #FF8C00]]"
        )

        self.location = Path(
            directories.temp
            / "{type}_{id}_{enc}".format(
                type=self.type,
                id=f"""{str(self.language)}{f'-{self.variables["flag"].lower()}' if self.variables['flag'] else ''}_{self.codec}""",
                enc="enc" if self.encrypted else "dec",
            )
        )

    def get_track_name(self) -> Optional[str]:
        """Return the base Track Name."""
        track_name = super().get_track_name() or ""
        flag = self.cc and "CC" or self.sdh and "SDH" or self.forced and "Forced"
        if flag:
            if track_name:
                flag = f" [{flag}]"
            track_name += flag
        return track_name or None

    def get_track_flag(self) -> Optional[str]:
        """Return the base Track Flag."""
        track_name = super().get_track_name() or ""
        flag = self.cc and "CC" or self.sdh and "SDH" or self.forced and "Forced"
        if flag:
            if track_name:
                flag = f" [{flag}]"
        return flag or None

    def __str__(self):
        return " | ".join(
            [
                x
                for x in [
                    "SUB",
                    f"[{self.codec}]",
                    f"{self.language}",
                    " ".join(
                        [
                            self.get_track_name() or "",
                            "[Original]" if self.is_original_lang else "",
                        ]
                    ).strip(),
                ]
                if x
            ]
        )

    @staticmethod
    def threading(title, service, directories, ctx, count=0):
        if any(
            not bool(os.path.isfile(f"{track.location}.srt"))
            for track in title.tracks.subtitles
        ):
            if not args__.dl.subs_only or args__.dl.audio_only and args__.dl.subs_only:
                log.info_(" - Downloading subtitles in background")
            elif args__.dl.subs_only and not args__.dl.audio_only:
                log.info_(" + Downloading Subtitles")

            for track in title.tracks.subtitles:
                out = track.location
                if not bool(os.path.isfile(f"{out}.srt")):
                    count = count + 1
                    if args__.dl.subs_only and not args__.dl.audio_only:
                        backward = "\x1b[80D\x1b[1A\x1b[2K" if count != 1 else ""
                        flag = (
                            f" [{track.variables['flag']}]"
                            if track.variables["flag"]
                            else ""
                        )
                        log.info_(
                            f'{backward}   {f"[bold #FF8C00]{track.language.display_name()}{flag}[/bold #FF8C00]"}'.rstrip(
                                "\r"
                            ),
                        )
                    if not bool(os.path.isfile(f"{out}.mp4")):
                        TextTrack.download.get(
                            track,
                            service,
                            directories,
                            title,
                            ctx,
                            headers=service.session.headers,
                        )
                    TextTrack.fix(track)

            if not any(
                not bool(os.path.isfile(f"{track.location}.srt"))
                for track in title.tracks.subtitles
            ):
                if args__.dl.subs_only:
                    log.info_(f"{clean_line}{clean_line} ✓ All Subtitles Downloaded")
            else:
                log.exit(f"{clean_line}{clean_line} x Could not complete all subtitles")
        else:
            log.info_(" ✓ Subtitles Already Downloaded ".rstrip("\n"))

        for track in title.tracks.subtitles:
            track.location = f"{track.location}.srt"

            # Delete subtitle if its empty
            subtitle = pysrt.open(track.location)
            if not subtitle.text:
                del title.tracks.subtitles[title.tracks.subtitles.index(track)]

    class download:
        def get(self, service, directories, title, ctx, name=None, headers=None):
            segmented = (
                type(self.url) == list
                or self.url.endswith("m3u8")
                or self.url.endswith("mpd")
                or "apple.com" in self.url
                or self.source == "RKTN"
            )

            if segmented:
                location = f"{self.location}.{'dash' if '.dash' in self.url[0] or '.mp4' in self.url[0] or '.m4s' in self.url[1] else 'mp4'}"
                if not os.path.isfile(config.directories.temp / location):
                    if (
                        (self.url.endswith("m3u8") or "apple.com" in self.url)
                        if type(self.url) != list
                        else (
                            self.url[0].endswith("m3u8") or "apple.com" in self.url[0]
                        )
                    ):
                        subtitle = asyncio.run(
                            TextTrack.download.m3u8(service.session, self)
                        )
                    else:
                        subtitle = Path(Track.download(self, title, ctx, headers))
                else:
                    subtitle = location
                if (
                    ".dash" in self.url[0]
                    or ".mp4" in self.url[0]
                    or ".m4s" in self.url[1]
                ):
                    subtitle = TextTrack.download.dash(service.session, self)
            else:
                subtitle_url = service.session.get(url=self.url)
                if subtitle_url.status_code != 200:
                    log.exit(
                        f" x Could not download subtitle with language '{self.language.language}'\n   Probably because of an HTTPError"
                    )
                subtitle_content = subtitle_url.text

                try:
                    data = subtitle_content.read()
                except AttributeError:
                    data = subtitle_content
                subtitle = Path(f"{self.location}.mp4")
                subtitle.write_text(data, encoding="utf8")
            return subtitle

        async def m3u8_segments(client, url):
            try:
                response = await client.get(url)
            except httpx.ConnectError:
                response = await client.get(url)
            return response.text

        async def m3u8(session, track):
            segments, duration = [], 0
            for segment in m3u8.load(track.url).segments:
                duration = duration + segment.duration
                if (
                    int(segment.duration) >= 60
                    or track.forced
                    and "empty" not in segment.absolute_uri
                ):
                    segments.append(
                        {"uri": segment.absolute_uri, "duration": segment.duration}
                    )

            uri_list = []
            if (
                len(segments) < 10 and duration < 600
            ):  # Assume no video is shorter than 10 minutes
                uri_list.append(
                    [sorted(segments, key=lambda x: x["duration"], reverse=True)][0][0][
                        "uri"
                    ]
                )
            else:
                abc, xyz, wtf = set(), [], []
                for seg in segments:
                    abc.add(seg["uri"].rsplit("/", 1)[0])
                    xyz.append(seg["uri"].rsplit("/", 1)[0])

                for k in abc:
                    wtf.append({"prefix": k, "count": xyz.count(k)})

                wtf = sorted(wtf, key=lambda x: x["count"], reverse=True)[0]
                for seg in segments:
                    if wtf["prefix"] in seg["uri"]:
                        uri_list.append(seg["uri"])

            tasks = []
            client = httpx.AsyncClient(
                transport=httpx.AsyncHTTPTransport(retries=1),
                proxies={"all://": getattr(args__.main, "proxy_uri", None)},
            )
            for uri in uri_list:
                tasks.append(
                    asyncio.create_task(TextTrack.download.m3u8_segments(client, uri))
                )

            subtext = await asyncio.gather(*tasks)
            with open(f"{track.location}.mp4", "w+") as subfile:
                for substring in subtext:
                    subfile.write(substring)

            await client.aclose()

            return Path(f"{track.location}.mp4")

        def dash(session, subtitle):
            dash_path = Path(f"{config.directories.temp}/dash_segments")
            if os.path.exists(dash_path):
                shutil.rmtree(dash_path, ignore_errors=True)
            dash_path.mkdir(exist_ok=False)

            for exec_ in ("mp4split", "mp4dash"):
                exec = shutil.which(exec_) or shutil.which(f"{exec_}.exe")
                if exec_ == "mp4split":
                    split_exec = exec
                elif exec_ == "mp4dash":
                    dash_exec = exec
                if not exec:
                    log.info_(
                        f"{clean_line} x Could not find {exec_!r} on this machine",
                        style="error",
                    )
                    exit()

            os.chdir(dash_path)
            split_file = subprocess.run(
                f'{split_exec} "{subtitle.location}.dash"',
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True,
                universal_newlines=True,
            )
            os.chdir(config.directories.temp)

            if split_file.returncode:
                log.info_(
                    f"{clean_line} x Could not split TextTrack {subtitle.map}",
                    style="error",
                )
                exit()

            mux_commands = (
                f'wine "{dash_exec}"'
                if platform == "linux" or platform == "linux2"
                else f'"{dash_exec}"'
            )
            mux_commands += " dash_segments"
            mux_commands += " *.m4s"
            mux_commands += f" {subtitle.location.name}"

            mux_segments = subprocess.run(
                mux_commands,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True,
                universal_newlines=True,
            )

            if mux_segments.returncode:
                log.info_(
                    f"{clean_line} x Could not mux segments of TextTrack {subtitle.map}",
                    style="error",
                )
                exit()

            os.rename(
                f"{subtitle.location.name}.{subtitle.codec.lower()}",
                f"{subtitle.location.name}.mp4",
            )
            shutil.rmtree(dash_path, ignore_errors=True)
            return Path(f"{subtitle.location}.mp4")

    class fix:
        def __init__(self, track):
            raw_data = open(f"{track.location}.mp4", "r+").read()

            self.clean_subtitle(track)
            self.remove_dupe_lines(track)
            if track.language._str_tag in [
                "ar",
                "ar-dz",
                "ar-bh",
                "ar-eg",
                "ar-iq",
                "ar-jo",
                "ar-kw",
                "ar-lb",
                "ar-ly",
                "ar-ma",
                "ar-om",
                "ar-qa",
                "ar-sa",
                "ar-sy",
                "ar-tn",
                "ar-ae",
                "ar-ye",
                "he",
                "ku",
                "fa",
                "ur",
            ]:
                self.rtl(track)
            self.clean_subtitle(track)

            shutil.copyfile(f"{track.location}.mp4", f"{track.location}.srt")
            with open(f"{track.location}.mp4", "w+") as raw_file:
                raw_file.seek(0)
                raw_file.write(raw_data)
                raw_file.truncate()

        def clean_subtitle(self, track):
            with open(f"{track.location}.mp4", "r+") as subfile:
                subtext = subfile.read()
                subtext = re.sub(
                    r"(.*\bposition:50.00%.*\bline:10.00%)\s*(.*)",
                    r"\1\n{\\an8}\2",
                    subtext,
                )

                subtext = re.sub(
                    r"(.*\bline:10%.*\bposition:50%.*)\s*(.*)",
                    r"\1\n{\\an8}\2",
                    subtext,
                )

                subtext = re.sub(
                    r"(.*\balign:middle line:0%,start position:50%,middle)\s*(.*)",
                    r"\1\n{\\an8}\2",
                    subtext,
                )

                subtext = re.sub(r"tt:", "", subtext)
                subtext = re.sub(r"âª", "♪", subtext)
                subtext = re.sub(r"Ã©", "é", subtext)
                subtext = re.sub(r"&rlm;", "\u202B", subtext)
                subtext = re.sub(r"&lrm;", "\u202A", subtext)
                subtext = re.sub(r"&gt;", ">", subtext)
                subtext = re.sub(r"&amp;", "&", subtext)
                subtext = re.sub(r"&nbsp;", "", subtext)
                subtext = re.sub(r"WEBVTT\n", "", subtext)
                subtext = re.sub(r"\nNOTE.*", "", subtext)
                subtext = re.sub(r"\n\s+\n", "\n", subtext)
                subtext = re.sub(r"\n\-\s+\n", "\n\n", subtext)
                subtext = re.sub(r" +", " ", subtext)
                subtext = re.sub(r" , ", ", ", subtext)
                subtext = re.sub(r"(?<=[.,])(?=[^\s\d\.\d\.\.\.])", r" ", subtext)
                subtext = re.sub(r"\n\.\.\.\s", r"\n...", subtext)
                subtext = re.sub(r" (position|align):.+", "", subtext)
                subtext = re.sub(r"</?c.+?>", "", subtext)
                subtext = re.sub(r"</?c>", "", subtext)
                subtext = re.sub(r">\.\.\.\s", r"\n...", subtext)
                subtext = re.sub(r"X-TIMESTAMP-MAP+(..*)", "", subtext)

                # NLziet Subtitles
                subtext = re.sub(r"\nNPO ONDERTITELING.*\n", "", subtext)
                subtext = re.sub(r"\ntt888.*\n", "", subtext)

                # Videoland Subtitles
                subtext = re.sub(r"\nep.*\n", "\n", subtext)
                subtext = re.sub(r"story:.*\n", "", subtext)
                subtext = re.sub(r"Title:.*\n", "", subtext)
                subtext = re.sub(r"LANG:.*\n", "", subtext)
                subtext = re.sub(r"air:.*\n", "", subtext)

                # DisneyPlus Subtitles
                subtext = re.sub(r"STYLE\n", "\n", subtext)
                subtext = re.sub(r"::cue.*\n", "", subtext)
                subtext = re.sub(r" font-family.*\n", "", subtext)
                subtext = re.sub(r" text-shadow.*\n", "", subtext)
                subtext = re.sub(r"\n}\n", "\n", subtext)

                subtext = re.sub(r"line:.*%, start", "\n", subtext)
                subtext = re.sub(r"line:.*%, end", "\n", subtext)
                subtext = re.sub(r"line:.*%", "\n", subtext)

                subtext = re.sub(r"\r\n", "\n", subtext)
                subtext = re.sub(r"\n\r", "\n", subtext)
                subtext = re.sub(r"\n\n\n", "\n \n", subtext)
                subtext = re.sub(r"\n\n<", "\n<", subtext)
                subtext = re.sub(r"(\b\d+\b) \n\n", r"\1\n", subtext)
                subtext = re.sub(r"\n(\b\d+\b)\n", r"\n\1\n", subtext)
                subtext = re.sub(
                    r"(?![^\n])\n(\b\d+\b):(\b\d+\b):(\b\d+\b).(\b\d+\b) --> (\b\d+\b):(\b\d+\b):(\b\d+\b).(\b\d+\b)\n",
                    r"\n\n\1:\2:\3.\4 --> \5:\6:\7.\8\n",
                    subtext,
                )
                subtext = re.sub(r"\n\n(\b\d+\b)\n\n(\b\d+\b)", r"\n\n\1\n\2", subtext)
                subtext = re.sub(r"(\b\d+\b)\n\n(\b\d+\b)", r"\1\n\2", subtext)
                subtext = re.sub(r"(?![^\n])(\n\d+\n)", r"\n\1", subtext)
                subtext = re.sub(r"\n\n\n", "\n\n", subtext)
                subtext = re.sub(r"\n\n\n(\b\d+\b)\n", r"\n\n\1\n", subtext)

                # Somehow Windows machines are having issues without this
                if sys.platform == "win32":
                    subtext = re.sub(r"\n\n", "\n", subtext)
                    subtext = re.sub(r"\n(\b\d+\b)\n", r"\n\n\1\n", subtext)

                subfile.seek(0)
                subfile.write(subtext)
                subfile.truncate()

        def remove_dupe_lines(self, track):
            content = []
            subtext = pysrt.open(f"{track.location}.mp4")
            for line in subtext:
                singleLine = line.text.split("\n")
                if len(singleLine) == 3:
                    line.text = "\n".join(
                        [singleLine[0], " ".join([singleLine[1], singleLine[2]])]
                    )
                line.text = re.sub(r"</i> <i>", " ", line.text)
                content.append(
                    {
                        "start": line.start.ordinal,
                        "end": line.end.ordinal,
                        "text": line.text,
                    }
                )

            def remove_dups(List, keyword=""):
                Added_ = set()
                Proper_ = []
                for L in List:
                    if L[keyword] not in Added_:
                        Proper_.append(L)
                        Added_.add(L[keyword])

                return Proper_

            content = remove_dups(content, "start")

            newsub = pysrt.SubRipFile()
            for index, line in enumerate(content):
                newsub.append(
                    pysrt.SubRipItem(
                        index=index + 1,
                        start=line["start"],
                        end=line["end"],
                        text=line["text"],
                    )
                )
            newsub.save(f"{track.location}.mp4")

        def rtl(self, track):
            with open(f"{track.location}.mp4", "r+") as subfile:
                data = subfile.readlines()
                subfile.seek(0)
                subfile.truncate()
                subfile.close()

            with open(f"{track.location}.mp4", "w+") as subfile:
                for idx, line in enumerate(data, start=1):
                    if (
                        line.strip() != ""
                        and "-->" not in line.strip()
                        and not line.strip().isdigit()
                    ):
                        line = re.sub(
                            "^",
                            unicodedata.lookup("RIGHT-TO-LEFT EMBEDDING"),
                            line,
                            re.MULTILINE,
                        )
                    if idx == 1:
                        line = "1"

                    subfile.write(line.strip())
                    subfile.write("\n")


class MenuTrack:
    line_1 = re.compile(r"^CHAPTER(?P<number>\d+)=(?P<timecode>[\d\\.]+)$")
    line_2 = re.compile(r"^CHAPTER(?P<number>\d+)NAME=(?P<title>[\d\\.]+)$")

    def __init__(self, number: int, title: str, timecode: str):
        self.id = f"chapter-{number}"
        self.number = number
        self.title = title
        if "." not in timecode:
            timecode += ".000"
        self.timecode = timecode

    def __bool__(self) -> bool:
        return bool(self.number and self.number >= 0 and self.title and self.timecode)

    def __repr__(self) -> str:
        """
        OGM-based Simple Chapter Format intended for use with MKVToolNix.

        This format is not officially part of the Matroska spec. This was a format
        designed for OGM tools that MKVToolNix has since re-used. More Information:
        https://mkvtoolnix.download/doc/mkvmerge.html#mkvmerge.chapters.simple
        """
        return "CHAPTER{num}={time}\nCHAPTER{num}NAME={name}".format(
            num=f"{self.number:02}", time=self.timecode, name=self.title
        )

    def __str__(self) -> str:
        return " | ".join(["CHP", f"[{self.number:02}]", self.timecode, self.title])

    @classmethod
    def loads(cls, data: str) -> MenuTrack:
        """Load chapter data from a string."""
        lines = [x.strip() for x in data.strip().splitlines(keepends=False)]
        if len(lines) > 2:
            return MenuTrack.loads("\n".join(lines))
        one, two = lines

        one_m = cls.line_1.match(one)
        two_m = cls.line_2.match(two)
        if not one_m or not two_m:
            SyntaxError
            log.exit(f"An unexpected syntax error near:\n{one}\n{two}")

        one_str, timecode = one_m.groups()
        two_str, title = two_m.groups()
        one_num, two_num = int(one_str.lstrip("0")), int(two_str.lstrip("0"))

        if one_num != two_num:
            SyntaxError
            log.exit(f"The chapter numbers ({one_num},{two_num}) does not match.")
        if not timecode:
            SyntaxError
            log.exit("The timecode is missing.")
        if not title:
            SyntaxError
            log.exit("The title is missing.")

        return cls(number=one_num, title=title, timecode=timecode)

    @classmethod
    def load(cls, path: Union[Path, str]) -> MenuTrack:
        """Load chapter data from a file."""
        if isinstance(path, str):
            path = Path(path)
        return cls.loads(path.read_text(encoding="utf8"))

    def dumps(self) -> str:
        """Return chapter data as a string."""
        return repr(self)

    def dump(self, path: Union[Path, str]) -> int:
        """Write chapter data to a file."""
        if isinstance(path, str):
            path = Path(path)
        return path.write_text(self.dumps(), encoding="utf8")


class Tracks:
    """
    Tracks.
    Stores video, audio, and subtitle tracks. It also stores chapter/menu entries.
    It provides convenience functions for listing, sorting, and selecting tracks.
    """

    TRACK_ORDER_MAP = {VideoTrack: 0, AudioTrack: 1, TextTrack: 2, MenuTrack: 3}

    def __init__(self, *args: Union[Tracks, list[Track], Track]):
        self.videos: list[VideoTrack] = []
        self.audio: list[AudioTrack] = []
        self.subtitles: list[TextTrack] = []
        self.temp_subtitles: list[TextTrack]
        self.chapters: list[MenuTrack] = []

        if args:
            self.add(as_list(*args))

    def __iter__(self) -> Iterator[AnyTrack]:
        return iter(as_list(self.videos, self.audio, self.subtitles))

    def __repr__(self) -> str:
        return "{name}({items})".format(
            name=self.__class__.__name__,
            items=", ".join([f"{k}={repr(v)}" for k, v in self.__dict__.items()]),
        )

    def __str__(self) -> str:
        rep = ""
        last_track_type = None
        tracks = [*list(self), *self.chapters]
        for track in sorted(tracks, key=lambda t: self.TRACK_ORDER_MAP[type(t)]):
            if type(track) != last_track_type:
                last_track_type = type(track)
                count = sum(type(x) is type(track) for x in tracks)
                rep += "{count} {type} Track{plural}{colon}\n".format(
                    count=count,
                    type=track.__class__.__name__.replace("Track", ""),
                    plural="s" if count != 1 else "",
                    colon=":" if count > 0 else "",
                )
            rep += f"{track}\n"

        return rep.rstrip()

    def remove_dupes(self):
        self.videos = [
            item
            for index, item in enumerate(self.videos)
            if item not in self.videos[:index]
        ]

        self.audio = [
            item
            for index, item in enumerate(self.audio)
            if item not in self.audio[:index]
        ]

        self.subtitles = [
            item
            for index, item in enumerate(self.subtitles)
            if item not in self.subtitles[:index]
        ]

        self.chapters = [
            item
            for index, item in enumerate(self.chapters)
            if item not in self.chapters[:index]
        ]

        return self

    class list:
        def __init__(
            self,
            title,
            all_tracks,
            selected_tracks,
        ):
            self.all_tracks = all_tracks
            self.selected_tracks = selected_tracks
            self.tree = Tree(
                "\n[cyan]TRACKS FROM[/cyan] "
                + f"{title.name.upper()} S{title.season:02d}E{title.episode:02d}"
                if title.episode
                else "\n[cyan]TRACKS FROM[/cyan] "
                + f"{title.name.upper()}{f' ({title.year})' if title.year else ''}",
                guide_style="",
            )

            if args__.dl.list == "SELECTED":
                self.all_tracks = self.selected_tracks

            if not args__.dl.audio_only and not args__.dl.subs_only:
                self.videos()

            if args__.dl.audio_only and args__.dl.subs_only or not args__.dl.subs_only:
                self.audios()

            if args__.dl.audio_only and args__.dl.subs_only or not args__.dl.audio_only:
                self.texts()

            log.info_(self.tree)
            return

        def videos(self):
            if args__.dl.list == "PREFERRED":
                self.all_tracks[0] = [
                    x
                    for x in self.all_tracks[0]
                    if args__.dl.video_codec in x.variables["codec"].replace(".", "")
                ]
                self.all_tracks[0] = [
                    x
                    for x in self.all_tracks[0]
                    if any(
                        r in x.variables["range"]
                        for r in args__.dl.range.replace("HDR+", "HDR10+").split("+")
                    )
                ]

            videos = self.tree.add(
                f"[content]VIDEO TRACKS[/content] [dim]({len(self.all_tracks[0])})[/dim]"
            )

            total_h264 = len(
                [x for x in self.all_tracks[0] if x.variables["codec"] == "H.264"]
            )
            h264 = videos.add(
                f"[content]H.264 TRACKS[/content] [dim]({total_h264})[/dim]"
            )

            total_h265 = len(
                [x for x in self.all_tracks[0] if x.variables["codec"] == "H.265"]
            )
            h265 = videos.add(
                f"[content]H.265 TRACKS[/content] [dim]({total_h265})[/dim]"
            )

            for video_type in (h264, h265):
                profile_ = (
                    "  PROFILE"
                    if any(
                        v.profile
                        for v in self.all_tracks[0]
                        if (
                            v.variables["codec"] == "H.264"
                            if video_type == h264
                            else v.variables["codec"] == "H.265"
                        )
                    )
                    else ""
                )
                video_type.add(
                    "[bold dim]RESOLUTION"
                    + "  CODEC"
                    + "  RANGE"
                    + profile_
                    + "  BITRATE"
                    + f"{' ' * max(len(str(video.bitrate // 1000)) for video in self.all_tracks[0])}FRAMERATE[/bold dim]"
                )

            bitrate_rjust = (
                max(len(str(video.bitrate // 1000)) for video in self.all_tracks[0]) + 2
            )

            for video in self.all_tracks[0]:
                video_type = h264 if video.variables["codec"] == "H.264" else h265

                profile_ = (
                    "  PROFILE"
                    if any(
                        v.profile
                        for v in self.all_tracks[0]
                        if (
                            v.variables["codec"] == "H.264"
                            if video_type == h264
                            else v.variables["codec"] == "H.265"
                        )
                    )
                    else ""
                )
                profile = video.profile.replace("MPL", "MAIN").replace("HPL", "HIGH")

                video_type.add(
                    f"{video.width}x{video.height}".rjust(10)
                    + f"  {video.variables['codec']}".rjust(5)
                    + f" {video.variables['range']}".rjust(7)
                    + f"{f' {profile}'.rjust(9) if profile_ else ''}"
                    + f"{f'{video.bitrate // 1000}'.rjust(bitrate_rjust)} kb/s"
                    + f"  {f'{video.fps:.3f} FPS' if video.fps else ''}",
                    style="dim"
                    if not any(v.id == video.id for v in self.selected_tracks[0])
                    else "",
                )

            if args__.dl.list in ["PREFERRED", "SELECTED"]:
                self.tree.children[0].children = [
                    x for x in self.tree.children[0].children if len(x.children) > 1
                ]

        def audios(self):
            if args__.dl.list == "PREFERRED":
                if args__.dl.audio_codec:
                    self.all_tracks[1] = [
                        x
                        for x in self.all_tracks[1]
                        if x.variables["codec"].replace("-", "")
                        == args__.dl.audio_codec.replace("-", "")
                        and x.language._str_tag in args__.dl.alang
                    ]
                self.all_tracks[1] = [
                    x for x in self.all_tracks[1] if str(x.language) in args__.dl.alang
                ]

            audios = self.tree.add(
                f"[content]AUDIO TRACKS[/content] [dim]({len(self.all_tracks[1])})[/dim]"
            )

            total_atmos = len(
                [
                    x
                    for x in self.all_tracks[1]
                    if not x.descriptive
                    and x.atmos
                    or not x.descriptive
                    and "16/JOC" in x.channels
                ]
            )
            atmos = audios.add(
                f"[content]DOLBY ATMOS AUDIO[/content] [dim]({total_atmos})[/dim]"
            )

            total_regular = len(
                [
                    x
                    for x in self.all_tracks[1]
                    if not x.descriptive and not x.atmos and "16/JOC" not in x.channels
                ]
            )
            regular = audios.add(
                f"[content]REGULAR AUDIO[/content] [dim]({total_regular})[/dim]"
            )

            total_descriptive = len([x for x in self.all_tracks[1] if x.descriptive])
            descriptive = audios.add(
                f"[content]DESCRIPTIVE AUDIO[/content] [dim]({total_descriptive})[/dim]"
            )

            lang_len = max(
                [
                    (
                        len(
                            Language.get(a.language, normalize=False)
                            .display_name()
                            .title()
                        ),
                        Language.get(a.language, normalize=False)
                        .display_name()
                        .title(),
                    )
                    for a in self.all_tracks[1]
                ]
            )

            codec_len = max(
                [
                    (
                        len(a.variables["codec"]),
                        a.variables["codec"],
                    )
                    for a in self.all_tracks[1]
                ]
            )

            for audio_type in (atmos, descriptive, regular):
                audio_type.add(
                    f"[bold dim]LANGUAGE{' ' * (2 if lang_len[0] <= 10 else lang_len[0] + 2 - 8)}"
                    + f"CODEC{' ' * (codec_len[0] - 3 if codec_len[0] > 3 else 2)}"
                    + "CH."
                    + "  BITRATE[/bold dim]"
                )

            for audio in sorted(
                self.all_tracks[1], key=lambda x: x.bitrate, reverse=True
            ):
                audio_type = (
                    atmos
                    if not audio.descriptive
                    and audio.atmos
                    or not audio.descriptive
                    and "16/JOC" in audio.channels
                    else descriptive
                    if audio.descriptive
                    else regular
                )

                language = (
                    Language.get(audio.language, normalize=False).display_name().title()
                )

                audio_type.add(
                    f"{language}{' ' * (10 - lang_len[0] if lang_len[0] <= 10 else lang_len[0] + 2 - len(language))}"
                    + f"{audio.variables['codec']}{' ' * (7 - codec_len[0] if codec_len[0] <= 3 else codec_len[0] + 2 - len(audio.variables['codec']))}"
                    + f"{'5.1' if audio.channels in ['16/JOC', '5.1'] else audio.channels}"
                    + f"  {audio.bitrate // 1000} kb/s".rjust(10)
                    + f"{'  [#FF5733]ORIGINAL[/#FF5733]' if audio.is_original_lang else ''}",
                    style="dim"
                    if not any(a.id == audio.id for a in self.selected_tracks[1])
                    else "",
                )

            if args__.dl.list in ["PREFERRED", "SELECTED"] and not args__.dl.subs_only:
                self.tree.children[0 if args__.dl.audio_only else 1].children = [
                    x
                    for x in self.tree.children[
                        0 if args__.dl.audio_only else 1
                    ].children
                    if len(x.children) > 1
                ]

        def texts(self):
            total_subs = len(self.all_tracks[2])
            total_regular = len(
                [
                    x
                    for x in self.all_tracks[2]
                    if not x.sdh and not x.cc and not x.forced
                ]
            )
            total_forced = len(
                [x for x in self.all_tracks[2] if x.forced and not x.sdh and not x.cc]
            )
            total_sdh = len(
                [x for x in self.all_tracks[2] if x.sdh and not x.cc and not x.forced]
            )
            total_cc = len(
                [x for x in self.all_tracks[2] if x.cc and not x.sdh and not x.forced]
            )

            texts = self.tree.add(
                f"[content]SUBTITLES[/content] [dim]({total_subs})[/dim]"
                if total_subs
                else "[warning]NO SUBTITLES AVAILABLE[/warning]"
                if "none" not in args__.dl.slang
                else "[warning]SUBTITLES NOT WANTED[/warning]"
            )
            regular = texts.add(
                f"[content]REGULAR SUBTITLES[/content] [dim]({total_regular})[/dim]"
            )
            if any(t.forced for t in self.all_tracks[2]):
                forced = texts.add(
                    f"[content]FORCED SUBTITLES[/content] [dim]({total_forced})[/dim]"
                )
            if any(t.sdh for t in self.all_tracks[2]):
                sdh = texts.add(
                    f"[content]SDH SUBTITLES[/content] [dim]({total_sdh})[/dim]"
                )
            if any(t.cc for t in self.all_tracks[2]):
                cc = texts.add(
                    f"[content]CLOSED CAPTIONS[/content] [dim]({total_cc})[/dim]"
                )

            for subtitle in self.all_tracks[2]:
                sub_type = (
                    forced
                    if subtitle.forced
                    else sdh
                    if subtitle.sdh
                    else cc
                    if subtitle.cc
                    else regular
                )
                sub_type.add(
                    Language.get(subtitle.language).display_name().title()
                    + f"{' [#FF5733]ORIGINAL[/#FF5733]' if subtitle.is_original_lang else ''}",
                    style="dim"
                    if not any(t.id == subtitle.id for t in self.selected_tracks[2])
                    else "",
                )

            if args__.dl.list in ["PREFERRED", "SELECTED"]:
                self.tree.children[2].children = [
                    x for x in self.tree.children[2].children if len(x.children) >= 1
                ]

    def get_wanted(titles, season, episode):
        args = arguments()

        wanted_list = []
        for wanted in args.dl.wanted.copy():
            wanted_list += [
                f"{int(wanted.split('x')[0]):02}x{int(wanted.split('x')[1]):02}"
            ]

        for title in titles.copy():
            if f"{int(title[season]):02}x{int(title[episode]):02}" not in wanted_list:
                del titles[titles.index(title)]

        if not titles:
            raise NoWanted

        return titles

    def exists(
        self,
        by_language: Optional[str] = None,
        by_id: Optional[str] = None,
        by_url: Optional[Union[str, list[str]]] = None,
    ) -> bool:
        """Check if a track already exists by various methods."""
        if by_id:  # recommended
            return any(x.id == by_id for x in self)
        if by_url:
            return any(x.url == by_url for x in self)
        if (
            by_language
        ):  # Just to make sure we won't have both SDH and non-SDH tracks with the same language
            return any(x.language == by_language for x in self)
        return False

    def add(self, tracks):
        """
        Add a provided track to its appropriate array
        and ensuring it's not a duplicate.
        """
        if isinstance(tracks, Tracks):
            tracks = [*list(tracks), *tracks.chapters]

        duplicates = 0
        if not tracks:
            return
        else:
            if not isinstance(tracks[0], MenuTrack):
                TextTracks = (
                    [x for x in tracks if isinstance(x, TextTrack)]
                    if type(tracks) == list
                    else [tracks]
                )
                if TextTracks:
                    if TextTracks[0].source in ["ATVP", "iT"]:
                        try:
                            TextTracks = [
                                x
                                for x in TextTracks
                                if any(
                                    cdn in as_list(x.url)[0].split("?")[1].split("&")
                                    for cdn in ["cdn=ak", "cdn=vod-ak-aoc.tv.apple.com"]
                                )
                            ]
                        except IndexError:
                            pass

                    for track in TextTracks:
                        if self.exists(by_id=track.id):
                            del track
                            duplicates += 1
                            continue

                    TextTracks_ = []
                    for track in TextTracks:
                        if (
                            not track.sdh
                            and not track.cc
                            and not track.forced
                            and not any(
                                str(track.language) == str(x.language)
                                for x in TextTracks_
                            )
                        ):
                            TextTracks_ += [track]

                    for track in TextTracks:
                        if track.sdh and not any(
                            str(track.language) == str(x.language) and x.sdh
                            for x in TextTracks_
                        ):
                            TextTracks_ += [track]
                        elif track.cc and not any(
                            str(track.language) == str(x.language) and x.cc
                            for x in TextTracks_
                        ):
                            TextTracks_ += [track]
                        elif track.forced and not any(
                            str(track.language) == str(x.language) and x.forced
                            for x in TextTracks_
                        ):
                            TextTracks_ += [track]

            for track in as_list(tracks):
                if self.exists(by_id=track.id):
                    del track
                    duplicates += 1
                    continue
                if isinstance(track, VideoTrack):
                    self.videos.append(track)
                elif isinstance(track, AudioTrack):
                    self.audio.append(track)
                elif isinstance(track, MenuTrack):
                    self.chapters.append(track)
                elif isinstance(track, TextTrack) and not self.subtitles:
                    self.subtitles = TextTracks_
                elif not isinstance(track, TextTrack):
                    ValueError
                    log.exit("Track type was not set or is invalid.")

    def print(self, level: int = logging.INFO) -> None:
        """Print the __str__ to log at a specified level."""
        for line in str(self).splitlines(keepends=False):
            log.log(level, line)

    def sort_videos(
        self, by_language: Optional[Sequence[Union[str, Language]]] = None
    ) -> None:
        """Sort video tracks by bitrate, and optionally language."""
        if not self.videos:
            return
        # bitrate
        self.videos = sorted(
            self.videos, key=lambda x: float(x.bitrate or 0.0), reverse=True
        )
        # language
        for language in reversed(by_language or []):
            if str(language) == "all":
                language = next(
                    (x.language for x in self.videos if x.is_original_lang), ""
                )
            if not language:
                continue
            self.videos = sorted(
                self.videos,
                key=lambda x: ""
                if is_close_match(language, [x.language])
                else str(x.language),
            )

    def sort_audio(
        self, by_language: Optional[Sequence[Union[str, Language]]] = None
    ) -> None:
        """Sort audio tracks by bitrate, descriptive, and optionally language."""
        if not self.audio:
            return
        # bitrate
        self.audio = sorted(
            self.audio, key=lambda x: float(x.bitrate or 0.0), reverse=True
        )
        # descriptive
        self.audio = sorted(
            self.audio, key=lambda x: str(x.language) if x.descriptive else ""
        )
        # language
        for language in reversed(by_language or []):
            if str(language) == "all":
                language = next(
                    (x.language for x in self.audio if x.is_original_lang), ""
                )
            if not language:
                continue
            self.audio = sorted(
                self.audio,
                key=lambda x: ""
                if is_close_match(language, [x.language])
                else str(x.language),
            )

    def sort_subtitles(self) -> None:
        """Sort subtitle tracks by language"""
        if not self.subtitles:
            return
        self.subtitles = sorted(self.subtitles, key=lambda x: str(x.language))

    def sort_chapters(self) -> None:
        """Sort chapter tracks by chapter number."""
        if not self.chapters:
            return
        # number
        self.chapters = sorted(self.chapters, key=lambda x: x.number)

    @staticmethod
    def select_by_language(
        languages: list[str], iterable: list[TrackT], one_per_lang: bool = True
    ) -> Iterator[TrackT]:
        """
        Filter a track list by language.

        If one_per_lang is True, only the first matched track will be returned for
        each language. It presumes the first match is what is wanted.

        This means if you intend for it to return the best track per language,
        then ensure the iterable is sorted in ascending order (first = best, last = worst).
        """
        if not iterable:
            return
        if "all" in languages:
            tracks = iterable
        else:
            tracks = list(
                filter(lambda x: is_close_match(x.language, languages), iterable)
            )
        if one_per_lang and "all" not in languages:
            for language in languages:
                match = get_closest_match(language, [x.language for x in tracks])
                if match:
                    yield next(x for x in tracks if x.language == match)
        else:
            tracks = []
            for track in iterable:
                if not any(t.language == track.language for t in tracks):
                    tracks.append(track)

            for track in tracks:
                yield track

    def select_videos(self):
        """
        Filter VideoTracks by the following criteria:
            - Codec
            - Resolution
            - Color Range

        It will return an HDR10 VideoTrack in the wanted quality with
        an DV VideoTrack with the lowest quality when injection is wanted.
        """
        from widevinely.utils.click import video_codec  # Otherwise CircularImportError

        # H.264 fallback if needed
        fallback_videos = [
            video
            for video in self.videos
            if video_codec(value=video.codec.lower()) == video_codec(value="h.264")
        ]

        # Only Dolby Vision metadata is needed for injection
        dv_track = [
            video
            for video in self.videos
            if video.dv
            and video.bitrate <= min(video.bitrate for video in self.videos if video.dv)
        ]

        # Filter on codec
        attempt = 0
        for videos in (self.videos, fallback_videos):
            attempt += 1
            self.videos = [
                video
                for video in videos
                if video_codec(value=video.codec.lower())
                == video_codec(
                    value=args__.dl.video_codec.lower() if attempt == 1 else "h.264"
                )
            ]

            if self.videos:
                break

        if not self.videos:
            log.exit(
                f"\nNo videos with codec {args__.dl.video_codec} available"
                f"{', neither it could fallback to H.264' if args__.dl.video_codec != 'H.264' else ''}."
            )

        # Filter on quality
        self.videos = self.filter_quality(self.videos)
        fallback_videos = self.filter_quality(fallback_videos)

        # Filter on range
        attempt = 0
        for videos in (self.videos, fallback_videos):
            attempt += 1
            self.videos = [
                video
                for video in videos
                if {
                    "HDR10": video.hdr10 or video.hdr10plus,
                    "HDR10+DV": video.hdr10 or video.hdr10plus,
                    "HLG": video.hlg,
                    "DV": video.dv,
                    "SDR": not video.hdr10
                    and not video.hdr10plus
                    and not video.hlg
                    and not video.dv,
                }.get((args__.dl.range or "").upper() if attempt == 1 else "SDR", True)
            ]

            if self.videos:
                break

        if not self.videos:
            log.exit(
                f"\nNo videos with range {args__.dl.range} available, neither it could fallback to H.264 SDR."
            )

        if any((video.hdr10 or video.hdr10plus) for video in self.videos) and dv_track:
            self.videos = [self.videos[0], dv_track[0]]
        else:
            self.videos = [self.videos[0]]

    def filter_quality(self, videos):
        # 1:1 resolution
        if [video for video in videos if video.resolution == args__.dl.quality]:
            return [video for video in videos if video.resolution == args__.dl.quality]
        
        # Resolution with 16:9 canvas
        if [video for video in videos if int(video.width * (9 / 16)) == args__.dl.quality]:
            return [video for video in videos if int(video.width * (9 / 16)) == args__.dl.quality]
        
        # AMZN weird resolution (1248x520)
        if [video for video in videos if video.width == 1248 and args__.dl.quality == 720]:
            return [video for video in videos if video.width == 1248 and args__.dl.quality == 720]
        
        # Anything thats considered SD
        if [video for video in videos if (video.width, video.height) < (1024, 576) and args__.dl.quality == "SD"]:
            return [video for video in videos if (video.width, video.height) < (1024, 576) and args__.dl.quality == "SD"]
        
        # Manifest quality
        if [video for video in videos if isinstance(video.extra, dict) and video.extra.get("quality") == args__.dl.quality]:
            return [video for video in videos if isinstance(video.extra, dict) and video.extra.get("quality") == args__.dl.quality]
        
        # Fallback to closest resolution with best bitrate
        if [video for video in videos if int(video.width * (9 / 16)) < args__.dl.quality]:
            return [video for video in videos if int(video.width * (9 / 16)) < args__.dl.quality]
        
        log.exit(
            f"\nNo videos with quality {args__.dl.quality}p or anything close available."
        )

    def select_audio(self):
        """
        Filter AudioTracks by the following criteria:
            - Descriptive Audio
            - Codecs
            - Channels
            - Languages
        """
        from widevinely.utils.click import (
            audio_codec,
            audio_channels,
        )  # Otherwise CircularImportError

        # Filter on descriptive audio
        if args__.dl.descriptive_audio:
            self.audio = [audio for audio in self.audio if audio.descriptive]
            if not self.audio:
                log.exit("\nNo descriptive audio available.")

        # Filter on codecs
        audio_tracks = []
        for audio_co in ("eac3", "ac3", "aac"):
            if audio_co == "eac3" and args__.dl.audio_codec != "EAC3":
                continue

            if audio_co == "ac3" and "AAC" in args__.dl.audio_codec:
                continue

            audio_tracks += [
                audio
                for audio in self.audio
                if audio_codec(value=audio.codec.lower())
                == audio_codec(value=audio_co.lower())
            ]

        self.audio = audio_tracks
        if not self.audio:
            log.exit(f"\nNo audio with codec {args__.dl.audio_codec} available.")

        # Filter on channels
        audio_tracks = []
        for audio_ch in ("atmos", "5.1", "2.0"):
            if audio_ch == "atmos" and args__.dl.audio_channels != "16/JOC":
                continue

            if audio_ch == "5.1" and args__.dl.audio_channels == "2.0":
                continue

            audio_tracks += [
                audio
                for audio in self.audio
                if audio_channels(value=audio.channels.lower())
                == audio_channels(value=audio_ch.lower())
            ]

        self.audio = audio_tracks
        if not self.audio:
            log.exit(f"\nNo audio with {args__.dl.audio_channels} channels available.")

        # Filter wanted languages
        self.audio = list(self.select_by_language(args__.dl.alang, self.audio))
        if not self.audio:
            log.exit(
                f"\nNo audio with the following languages {', '.join(args__.dl.alang)} available."
            )

        # Update codec variable and remove duplicates
        self.audio = [
            item
            for index, item in enumerate(self.audio)
            if item not in self.audio[:index]
        ]
        for audio in self.audio:
            audio.variables["codec"] = audio_codec(value=audio.codec)

    def select_subtitles(self):
        """
        Make sure we get all subtitles but only SDH or CC subtitles
        when there is no regular subtitle for that language available
        """
        if args__.dl.flang:
            if "all" in args__.dl.flang:
                self.subtitles = [x for x in self.subtitles if x.forced or not x.forced]
            elif "none" not in args__.dl.flang:
                self.subtitles = [
                    x
                    for x in self.subtitles
                    if not x.forced or is_close_match(x.language, args__.dl.flang)
                ]
            else:
                self.subtitles = list(filter(lambda x: not x.forced, self.subtitles))

        regular = list(
            self.select_by_language(
                args__.dl.slang,
                [x for x in self.subtitles if not x.cc and not x.sdh and not x.forced],
                one_per_lang=True,
            )
        )

        forced = list(
            self.select_by_language(
                args__.dl.flang,
                [x for x in self.subtitles if x.forced and not x.sdh and not x.cc],
                one_per_lang=True,
            )
        )

        sdh = list(
            self.select_by_language(
                args__.dl.slang,
                [x for x in self.subtitles if x.sdh and not x.cc and not x.forced],
                one_per_lang=True,
            )
        )

        cc = list(
            self.select_by_language(
                args__.dl.slang,
                [x for x in self.subtitles if x.cc and not x.sdh and not x.forced],
                one_per_lang=True,
            )
        )

        self.subtitles = regular + forced

        for sdh_sub in sdh:
            if not any(sdh_sub.language == s.language for s in self.subtitles):
                self.subtitles += [sdh_sub]
        for cc_sub in cc:
            if not any(cc_sub.language == s.language for s in self.subtitles):
                self.subtitles += [cc_sub]

        if any(
            "nl-NL" in x.language._str_tag or x.language._str_tag == "nl"
            for x in self.subtitles
            if not x.forced
        ) and any(
            "nl-BE" in x.language._str_tag for x in self.subtitles if not x.forced
        ):
            for x in self.subtitles:
                if x.language._str_tag == "nl-BE" and not x.forced:
                    del self.subtitles[self.subtitles.index(x)]
        if any(
            "nl-NL" in x.language._str_tag or x.language._str_tag == "nl"
            for x in self.subtitles
            if x.forced
        ) and any("nl-BE" in x.language._str_tag for x in self.subtitles if x.forced):
            for x in self.subtitles:
                if x.language._str_tag == "nl-BE" and x.forced:
                    del self.subtitles[self.subtitles.index(x)]

        self.subtitles = sorted(
            self.subtitles, key=lambda x: str(x.language), reverse=False
        )

    def export_chapters(self, to_file: Optional[Union[Path, str]] = None) -> str:
        """Export all chapters in order to a string or file."""
        self.sort_chapters()
        data = "\n".join(map(repr, self.chapters))
        if to_file:
            to_file = Path(to_file)
            to_file.parent.mkdir(parents=True, exist_ok=True)
            to_file.write_text(data, encoding="utf8")
        return data

    # converter code

    @staticmethod
    def pt_to_sec(d):
        if isinstance(d, float):
            return d
        if d[0:2] == "P0":
            d = d.replace("P0Y0M0DT", "PT")
        if d[0:2] != "PT":
            ValueError
            log.exit("Input data is not a valid time string.")
        d = d[2:].upper()  # skip `PT`
        m = re.findall(r"([\d.]+.)", d)
        return sum(
            float(x[0:-1]) * {"H": 60 * 60, "M": 60, "S": 1}[x[-1].upper()] for x in m
        )

    @staticmethod
    def from_m3u8(*args, **kwargs):
        from widevinely import parsers

        return parsers.m3u8.parse(*args, **kwargs)

    @staticmethod
    def from_mpd(*args, **kwargs):
        from widevinely import parsers

        return parsers.mpd.parse(*args, **kwargs)

    def mux(
        self,
        service,
        title,
        directories,
        extension,
        default_audio=None,
        default_subtitle=None,
    ):
        """
        Takes the Video, Audio and Subtitle Tracks, and muxes them into an MKV container.
        It will attempt to detect Forced/Default tracks, and will try to parse the language codes of the Tracks
        """
        for track in self:
            if "_dec" not in str(track.location):
                log.exit(f" x {track.type} {track.map} is not properly decrypted")
            if not os.path.isfile(track.location) and not os.path.isfile(
                f"{track.location}.srt"
            ):
                log.exit(f" x {track.type} {track.map} is not downloaded yet")

        mkvmerge_exec = shutil.which("mkvmerge")
        if not mkvmerge_exec:
            log.exit(f"{clean_line} x Mkvmerge executable could not be found.")

        mkvmerge_args = [
            mkvmerge_exec,
            "--output",
            str(directories.temp / f"{title.filename}.muxed.{extension}"),
        ]
        for i, vt in enumerate(self.videos):
            mediainfo = MediaInfo.parse(vt.location)
            location = (
                f"{directories.temp}/{'HDR10+' if self.videos[0].hdr10plus else 'HDR10'}-DV.hevc"
                if len(self.videos) > 1
                else self.videos[0].location
            )
            if not location:
                log.exit(" x Somehow a VideoTrack was not downloaded before muxing")

            if mediainfo.video_tracks[0].encryption:
                log.exit(f" x {vt.type} {vt.map} is not properly decrypted")

            original_framerate = (
                mediainfo.tracks[1].other_frame_rate[0].split("(")[1].split(")")[0]
                if "(" in mediainfo.tracks[1].other_frame_rate[0]
                else mediainfo.tracks[1].other_frame_rate[0].replace(" FPS", "")
            )

            mkvmerge_args.extend(
                [
                    "--language",
                    "0:und",
                    "--disable-language-ietf",
                    "--default-track",
                    f"0:{i == 0}",
                    "--compression",
                    "0:none",  # disable extra compression
                    "--default-duration",
                    f"0:{original_framerate}fps",  # native framerate
                    "(",
                    str(location),
                    ")",
                ]
            )
            break

        for at in self.audio:
            mediainfo = MediaInfo.parse(at.location)

            for lang in args__.dl.default_audio:
                if any(lang in audio.language._str_tag for audio in self.audio):
                    default_audio = [
                        x.language._str_tag
                        for x in self.audio
                        if lang in x.language._str_tag
                    ][0]
                    break

            if not default_audio:
                default_audio = str(title.original_lang)

            default_audio = str(at.language) == default_audio

            raw_language = Language.get(at.language).autonym().title()
            if at.language._str_tag == "nl-BE":
                raw_language = "Vlaams"

            commercial_name = mediainfo.audio_tracks[0].commercial_name
            if mediainfo.audio_tracks[0].channel_s == 2:
                channels = "2.0"
            elif mediainfo.audio_tracks[0].channel_s == 6:
                channels = "5.1"

            if mediainfo.audio_tracks[0].encryption:
                log.exit(f"{clean_line}{at.type} {at.map} is not properly decrypted")

            mkvmerge_args.extend(
                [
                    "--track-name",
                    f"0:{raw_language} [{commercial_name} {channels}]",
                    "--language",
                    f"0:{at.language}",
                    "--disable-language-ietf",
                    "--default-track",
                    f"0:{default_audio}",
                    "--visual-impaired-flag",
                    f"0:{at.descriptive}",
                    "--original-flag",
                    f"0:{at.is_original_lang}",
                    "--compression",
                    "0:none",  # disable extra compression
                    "(",
                    at.location,
                    ")",
                ]
            )

        for st in self.subtitles:

            for lang in args__.dl.default_subtitle:
                if any(
                    lang in subtitle.language._str_tag for subtitle in self.subtitles
                ):
                    default_subtitle = [
                        x.language._str_tag
                        for x in self.subtitles
                        if lang in x.language._str_tag
                    ][0]
                    break

            if not default_subtitle:
                default_subtitle = str(title.original_lang)

            default_subtitle = (
                str(st.language) == default_subtitle
                and not st.sdh
                and default_subtitle != default_audio
            )

            raw_language = (
                "Nederlands"
                if st.language._str_tag == "nl-NL"
                else "Vlaams"
                if st.language._str_tag == "nl-BE"
                else Language.get(st.language).autonym().title()
            )

            if ".srt" not in str(st.location):
                st.location = Path(f"{st.location}.srt")

            mkvmerge_args.extend(
                [
                    "--track-name",
                    f"0:{raw_language}{' [' + st.variables['flag'] + ']' if st.variables['flag'] else ''}",
                    "--language",
                    f"0:{st.language}",
                    "--disable-language-ietf",
                    "--sub-charset",
                    "0:UTF-8",
                    "--forced-track",
                    f"0:{st.forced}",
                    "--default-track",
                    f"0:{default_subtitle}",
                    "--hearing-impaired-flag",
                    f"0:{st.sdh}",
                    "--original-flag",
                    f"0:{st.is_original_lang}",
                    "--compression",
                    "0:none",  # disable extra compression (probably zlib)
                    "(",
                    st.location,
                    ")",
                ]
            )
            try:
                if service.bumper:
                    mkvmerge_args.extend(["--sync", "0:3008"])
            except Exception:
                pass

        if self.chapters:
            location = str(config.filenames.chapters).format(filename=title.filename)
            self.export_chapters(location)
            mkvmerge_args.extend(["--chapters", str(location)])

        # let potential failures go to caller, caller should handle
        muxing = subprocess.Popen(mkvmerge_args, stdout=subprocess.PIPE, text=True)
        for line in iter(muxing.stdout.readline, ""):
            if "Progress" in line.strip():
                progress = line.replace("\n", "").replace("Progress:", "Muxing:")
                log.info_(f"{clean_line} + {progress}")
            if "Multiplexing took" in line.strip():
                multiplextook = (
                    line.replace("\n", "")
                    .replace("Multiplexing took", "Succesfully muxed in")
                    .replace(".", "")
                )
                log.info_(f"{clean_line} ✓ {multiplextook} ")
            if "Error" in line.strip():
                if os.path.isfile(
                    str(
                        directories.temp
                        / f"{title.filename}.muxed.{'mka' if args__.dl.audio_only else 'mks' if args__.dl.subs_only else 'mkv'}"
                    )
                ):
                    os.remove(
                        str(
                            directories.temp
                            / f"{title.filename}.muxed.{'mka' if args__.dl.audio_only else 'mks' if args__.dl.subs_only else 'mkv'}"
                        )
                    )
                log.exit(f"{clean_line} x Muxing Failed: {line}")

        return muxing

    def mux_mp4(self, title, directories):
        """
        Takes the Video, Audio and Subtitle Tracks, and muxes them into an MPEG4 container.
        It will attempt to detect Forced/Default tracks, and will try to parse the language codes of the Tracks
        """
        for track in self:
            if "_dec" not in str(track.location):
                log.exit(f" x {track.type} {track.map} is not properly decrypted")
            if not os.path.isfile(track.location) and not os.path.isfile(
                f"{track.location}.srt"
            ):
                log.exit(f" x {track.type} {track.map} is not downloaded yet")

        for track in self.videos:
            if os.path.isfile(track.location):
                if not os.path.isfile(directories.temp / "DV.hevc"):
                    log.info_(f"{clean_line} + Extracting Dolby Vision stream")
                    extract_stream = subprocess.run(
                        [
                            "ffmpeg",
                            "-i",
                            str(track.location),
                            "-c:v",
                            "copy",
                            "-vbsf",
                            "hevc_mp4toannexb",
                            "-f",
                            "hevc",
                            directories.temp / "DV.hevc",
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    if extract_stream.returncode:
                        log.exit(
                            f"{clean_line} x Failed extracting Dolby Vision stream"
                        )

        for at in self.audio:
            if os.path.isfile(at.location):
                file = f"{at.type}_{at.language}.{at.variables['codec'].lower()}"
                if not os.path.isfile(directories.temp / file) and not os.path.isfile(
                    directories.temp / file.replace("eac3", "ec3")
                ):
                    log.info_(f"{clean_line} + Extracting AUDIO stream")
                    extract_stream = subprocess.run(
                        [
                            "ffmpeg",
                            "-i",
                            str(at.location),
                            "-codec",
                            "copy",
                            directories.temp / file,
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    if extract_stream.returncode:
                        log.exit(f"{clean_line} x Failed extracting audio stream")
                at.location = directories.temp / file.replace("eac3", "ec3")
                if os.path.isfile(directories.temp / file):
                    os.rename(
                        directories.temp / file,
                        directories.temp / file.replace("eac3", "ec3"),
                    )

        if not os.path.isfile(directories.temp / "dv_output.mp4"):
            log.info_(f"{clean_line} + Muxing Dolby Vision and AUDIO stream")
            video_info = MediaInfo.parse(self.videos[0].location)

            mux_args = [
                "mp4muxer",
                "--input-file",
                directories.temp / "DV.hevc",
                "--media-lang",
                "und",
                "--input-video-frame-rate",
                video_info.tracks[1].other_frame_rate[0].split("(")[1].split(")")[0]
                if "(" in video_info.tracks[1].other_frame_rate[0]
                else video_info.tracks[1].other_frame_rate[0].replace(" FPS", ""),
            ]

            for at in self.audio:
                mux_args.extend(
                    [
                        "--input-file",
                        at.location,
                        "--media-lang",
                        Language.get(at.language).to_alpha3(),
                    ]
                )

            mux_args.extend(
                [
                    "--dv-profile",
                    "5",
                    "--mpeg4-comp-brand",
                    "mp42,iso6,isom,msdh,dby1",
                    "--overwrite",
                    "--output-file",
                    directories.temp / "dv_output.mp4",
                ]
            )

            muxing = subprocess.run(
                mux_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            if muxing.returncode:
                log.exit(f"{clean_line} x Failed muxing Dolby Vision and AUDIO stream")

        if os.path.isfile(directories.temp / "dv_output.mp4"):
            if not os.path.isfile(directories.temp / f"{title.filename}.muxed.mp4"):
                log.info_(f"{clean_line} + Adding Subtitles to Video")
                subs_args = ["mp4box", "-add", directories.temp / "dv_output.mp4"]

                for st in self.subtitles:
                    for lang in args__.dl.default_subtitle:
                        if lang == "orig":
                            default_subtitle = "orig"
                            break
                        elif any(
                            lang in subtitle.language._str_tag
                            for subtitle in self.subtitles
                        ):
                            default_subtitle = [
                                x.language._str_tag
                                for x in self.subtitles
                                if lang in x.language._str_tag
                            ][0]
                            break

                    raw_language = (
                        "Nederlands"
                        if st.language._str_tag == "nl-NL"
                        else "Vlaams"
                        if st.language._str_tag == "nl-BE"
                        else Language.get(st.language).autonym().title()
                    )

                    subs_args.extend(
                        [
                            "-add",
                            f"{st.location}:lang={Language.get(st.language).to_alpha3()}"
                            f":name={raw_language}{' [' + st.variables['flag'] + ']' if st.variables['flag'] else ''}"
                            f"{':txtflags=0xC0000000' if st.forced else ''}"
                            f"{':group=1' if default_subtitle == 'orig' and st.is_original_lang and not st.sdh else ':group=1' if st.language._str_tag == default_subtitle and not st.sdh else ''}",
                        ]
                    )

                subs_args.extend(
                    [
                        "-brand",
                        "mp42isom",
                        "-ab",
                        "dby1",
                        "-no-iod",
                        directories.temp / f"{title.filename}.muxed.mp4",
                    ]
                )

                add_subs = subprocess.run(
                    subs_args,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                if add_subs.returncode:
                    log.exit(f"{clean_line} x Failed adding subtitles to Video")

    class DV_INJECTION:
        def __init__(self, videos) -> None:
            """
            Takes the Dolby Vision and HDR10(+) streams out of the VideoTracks.
            It will then attempt to inject the Dolby Vision metadata layer to the HDR10(+) stream.
            """
            global directories
            from widevinely.config import directories  # else: CircularImportError

            self.videos = videos
            self.rpu_file = "RPU.bin"
            self.hdr_type = (
                "HDR10+" if any(video.hdr10plus for video in self.videos) else "HDR10"
            )
            self.hevc_file = f"{self.hdr_type}-DV.hevc"

            log.info_("\nDOLBY VISION METADATA INJECTION\n", style="title")

            if any(not os.path.isfile(video.location) for video in self.videos):
                log.exit(
                    " - One of the VideoTracks was not downloaded before injection."
                )

            if not any(video.dv for video in self.videos) or not any(
                (video.hdr10 or video.hdr10plus) for video in self.videos
            ):
                log.exit(
                    " - Two VideoTracks available but one of them is not DV nor HDR10(+)."
                )

            if os.path.isfile(directories.temp / self.hevc_file):
                log.info_(f"{clean_line} ✓ Already Injected")
                return

            for video in videos:
                self.extract_stream(video)

            self.extract_rpu([video for video in videos if video.dv][0])
            if os.path.isfile(directories.temp / "RPU_UNT.bin"):
                self.rpu_file = "RPU_UNT.bin"
                self.level_6()
                self.mode_3()

            self.injecting()

            log.info_(f"{clean_line} ✓ Injection Completed")

        def extract_stream(self, video):
            type_ = "HDR10+" if video.hdr10plus else "HDR10" if video.hdr10 else "DV"
            if os.path.isfile(Path(directories.temp / f"{type_}.hevc")):
                return

            log.info_(
                f"{clean_line} + Extracting {'Dolby Vision' if type_ == 'DV' else type_} stream"
            )
            extract_stream = subprocess.run(
                [
                    "ffmpeg",
                    "-i",
                    video.location,
                    "-c:v",
                    "copy",
                    "-vbsf",
                    "hevc_mp4toannexb",
                    "-f",
                    "hevc",
                    Path(directories.temp / f"{type_}.hevc"),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if extract_stream.returncode:
                Path.unlink(Path(directories.temp / f"{type_}.hevc"))
                log.exit(
                    f"{clean_line} x Failed extracting {'Dolby Vision' if type_ == 'DV' else type_} stream"
                )

        def extract_rpu(self, video, untouched=False):
            if os.path.isfile(directories.temp / "RPU.bin") or os.path.isfile(
                directories.temp / "RPU_UNT.bin"
            ):
                return

            log.info_(
                f"{clean_line} + Extracting{' untouched ' if untouched else ' '}RPU from Dolby Vision stream"
            )

            extraction_args = ["dovi_tool"]
            if not untouched:
                extraction_args += ["--mode", "3"]
            extraction_args += [
                "extract-rpu",
                directories.temp / "DV.hevc",
                "-o",
                directories.temp / f"{'RPU' if not untouched else 'RPU_UNT'}.bin",
            ]

            rpu_extraction = subprocess.run(
                extraction_args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            if rpu_extraction.returncode:
                Path.unlink(
                    directories.temp / f"{'RPU' if not untouched else 'RPU_UNT'}.bin"
                )
                if b"MAX_PQ_LUMINANCE" in rpu_extraction.stderr:
                    self.extract_rpu(video, untouched=True)
                elif b"Invalid PPS index" in rpu_extraction.stderr:
                    log.exit(
                        f"{clean_line} x Dolby Vision VideoTrack seems to be corrupt"
                    )
                else:
                    log.exit(
                        f"{clean_line} x Failed extracting{' untouched ' if untouched else ' '}RPU from Dolby Vision stream"
                    )

        def level_6(self):
            """Edit RPU Level 6 values"""
            with open(directories.temp / "L6.json", "w+") as level6_file:
                level6 = {
                    "cm_version": "V29",
                    "length": 0,
                    "level6": {
                        "max_display_mastering_luminance": 1000,
                        "min_display_mastering_luminance": 1,
                        "max_content_light_level": 0,
                        "max_frame_average_light_level": 0,
                    },
                }

                json.dump(level6, level6_file, indent=3)

            if not os.path.isfile(directories.temp / "RPU_L6.bin"):
                log.info_(f"{clean_line} + Editing RPU Level 6 values")
                level6 = subprocess.run(
                    [
                        "dovi_tool",
                        "editor",
                        "-i",
                        directories.temp / self.rpu_file,
                        "-j",
                        directories.temp / "L6.json",
                        "-o",
                        directories.temp / "RPU_L6.bin",
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )

                if level6.returncode:
                    Path.unlink(directories.temp / "RPU_L6.bin")
                    log.exit(f"{clean_line} x Failed editing RPU Level 6 values")

        def mode_3(self):
            """Convert RPU to Mode 3"""
            with open(directories.temp / "M3.json", "w+") as mode3_file:
                json.dump({"mode": 3}, mode3_file, indent=3)

            if not os.path.isfile(directories.temp / "RPU_M3.bin"):
                log.info_(f"{clean_line} + Converting RPU to Mode 3")
                mode3 = subprocess.run(
                    [
                        "dovi_tool",
                        "editor",
                        "-i",
                        directories.temp / self.rpu_file,
                        "-j",
                        directories.temp / "M3.json",
                        "-o",
                        directories.temp / "RPU_M3.bin",
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )

                if mode3.returncode:
                    Path.unlink(directories.temp / "RPU_M3.bin")
                    log.exit(f"{clean_line} x Failed converting RPU to Mode 3")

            self.rpu_file = "RPU_M3.bin"

        def injecting(self):
            if os.path.isfile(directories.temp / self.hevc_file):
                return

            log.info_(
                f"{clean_line} + Injecting Dolby Vision metadata into {self.hdr_type} stream"
            )

            inject = subprocess.run(
                [
                    "dovi_tool",
                    "inject-rpu",
                    "-i",
                    directories.temp / f"{self.hdr_type}.hevc",
                    "--rpu-in",
                    directories.temp / self.rpu_file,
                    "-o",
                    directories.temp / self.hevc_file,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            if inject.returncode:
                Path.unlink(directories.temp / self.hevc_file)
                log.exit(
                    f"{clean_line} x Failed injecting Dolby Vision metadata into HDR10 stream"
                )
