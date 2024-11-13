import base64
import math
import re
import urllib.parse
import uuid
from copy import copy
from hashlib import md5

from langcodes import Language
from langcodes.tag_parser import LanguageTagError
from typing import Any, Optional
from pywidevinely import Cdm
from widevinely.objects import AudioTrack, TextTrack, Track, Tracks, VideoTrack
from widevinely.utils import logger, is_close_match
from widevinely.utils.xml import load_xml
from pywidevinely import PSSH
from widevinely.utils.exceptions import *

log = logger.getLogger("mpd.parser")


def parse(*, url=None, data=None, lang, source, session=None):
    """
    Convert an MPEG-DASH MPD (Media Presentation Description) document to a Tracks object
    with Video, Audio and Subtitle Track objects where available. This isn't using any
    specific MPD parser since it's XML format, lxml sufficed. There is a nice parser
    project but it has issues to do with ContentProtection so I cannot yet use it.

    :param data: The MPD document as a string.
    :param source: Source tag for the returned tracks.
    :param lang: Preferably the original-recorded language of the content in ISO alpha 2 format.
        It will be used as a fallback if a track has no language, and for metadata like if
        the track should be a default track.
    :param url: The original remote url of the MPD document if available. This is used to
        calculate the base URL for the direct URLs.

    Don't forget to manually handle the addition of any needed or extra information or values.
    Like `encrypted`, `pssh`, `hdr10`, `dv`, e.t.c. Essentially anything that is per-service
    should be looked at. Some of these values like `pssh` will try to be set automatically
    if possible but if you definitely have the values in the service, then set them.

    Example:
        url = "http://media.developer.dolby.com/DolbyVision_Atmos/profile8.1_DASH/p8.1.mpd"
        session = requests.Session(headers={"X-Example": "foo"})
        tracks = Tracks.from_mpds(session.get(url).text, url=url, source="DOLBY", lang="en")
    """
    tracks = []
    if not session:
        log.exit("\nA session is required to parse the tracks from an MPD manifest")
    if not data:
        if not url:
            log.exit("\nNeither a URL nor a document was provided to Tracks.from_mpd")
        data = session.get(url).text

    if "Forbidden" in data or "AccessDenied" in data:
        raise ManifestNotAvailable(reason="Forbidden.")

    if "Error" in data:
        raise ManifestNotAvailable()

    root = load_xml(data)
    OldBaseURL = ""
    NewBaseURL = ""
    if root.tag != "MPD":
        if source == "PMTP":
            return  # Known Issue, can be skipped
        ValueError
        log.exit("Non-MPD document provided to Tracks.from_mpds")

    for period in root.findall("Period"):
        if (
            source == "HULU"
            and next(iter(period.xpath("SegmentType/@value")), "content") != "content"
        ):
            continue

        period_base_url = period.findtext("BaseURL") or root.findtext("BaseURL")
        if (
            url
            and not period_base_url
            or not re.match("^https?://", period_base_url.lower())
        ):
            url = str(url)
            period_base_url = urllib.parse.urljoin(url, period_base_url)

        for adaptation_set in period.findall("AdaptationSet"):
            if any(
                x.get("schemeIdUri") == "http://dashif.org/guidelines/trickmode"
                for x in adaptation_set.findall("EssentialProperty")
                + adaptation_set.findall("SupplementalProperty")
            ):
                # Skip trick mode streams (used for fast forward/rewind)
                continue

            for rep in adaptation_set.findall("Representation"):
                # content type
                content_type = adaptation_set.attrib.get("contentType")
                if not content_type or content_type not in [
                    "video",
                    "audio",
                    "image",
                    "text",
                ]:
                    try:
                        content_type = next(
                            x
                            for x in [
                                rep.get("contentType"),
                                rep.get("mimeType"),
                                adaptation_set.get("contentType"),
                                adaptation_set.get("mimeType"),
                            ]
                            if bool(x)
                        )
                    except StopIteration:
                        ValueError
                        log.exit("No content type value could be found")
                    else:
                        content_type = content_type.split("/")[0]
                if content_type.startswith("image"):
                    continue  # most likely seek thumbnails
                # codec
                codecs = rep.get("codecs") or adaptation_set.get("codecs")
                if content_type == "text":
                    mime = adaptation_set.get("mimeType")
                    if mime and not mime.endswith("/mp4"):
                        codecs = mime.split("/")[1]
                # language
                track_lang: Optional[Language] = None
                for lang_ in [rep.get("lang"), adaptation_set.get("lang"), str(lang)]:
                    lang_ = (lang_ or "").strip()
                    if not lang_:
                        continue
                    try:
                        t = Language.get(lang_.split("-")[0])
                        if t == Language.get("und") or not t.is_valid():
                            raise LanguageTagError()
                    except LanguageTagError:
                        continue
                    else:
                        track_lang = Language.get(lang_)
                        break
                if not track_lang and lang:
                    track_lang = Language.get(lang)
                # content protection
                protections = rep.findall("ContentProtection") + adaptation_set.findall(
                    "ContentProtection"
                )
                encrypted = bool(protections)
                pssh = None
                pssh_b64 = None
                kid = None
                for protection in protections:
                    # For HMAX, the PSSH has multiple keys but the PlayReady ContentProtection tag
                    # contains the correct KID
                    if protection.get("value") == "cenc":
                        kid = protection.get(r"{urn:mpeg:cenc:2013}default_KID")
                    else:
                        kid = protection.get("default_KID")
                    if kid:
                        kid = uuid.UUID(kid).hex
                    else:
                        kid = protection.get("kid")
                        if kid:
                            kid = uuid.UUID(bytes_le=base64.b64decode(kid)).hex
                    if (protection.get("schemeIdUri") or "").lower() != Cdm.urn:
                        continue

                    if protection.findtext("pssh"):
                        pssh = PSSH(protection.findtext("pssh"))

                if kid:
                    array_of_bytes = bytearray(b"\x00\x00\x002pssh\x00\x00\x00\x00")
                    array_of_bytes.extend(
                        bytes.fromhex("edef8ba979d64acea3c827dcd51d21ed")
                    )
                    array_of_bytes.extend(b"\x00\x00\x00\x12\x12\x10")
                    array_of_bytes.extend(bytes.fromhex(kid.replace("-", "")))
                    pssh_b64 = base64.b64encode(
                        bytes.fromhex(array_of_bytes.hex())
                    ).decode("utf-8")
                    if not pssh:
                        pssh = PSSH(pssh_b64)

                rep_base_url = rep.findtext("BaseURL")
                if rep_base_url and source not in [
                    "DSCP",
                    "DSNY",
                ]:  # TODO: Don't hardcode services
                    # this mpd allows us to download the entire file in one go, no segmentation necessary!
                    if not re.match("^https?://", rep_base_url.lower()):
                        period_base_url = str(period_base_url)
                        rep_base_url = urllib.parse.urljoin(
                            period_base_url, rep_base_url
                        )
                    try:
                        query = url.query
                    except Exception:
                        query = urllib.parse.urlparse(url).query
                    if query and not urllib.parse.urlparse(rep_base_url).query:
                        rep_base_url += "?" + query
                    track_url = rep_base_url
                else:
                    # this mpd provides no way to download the entire file in one go :(
                    segment_template = rep.find("SegmentTemplate")
                    if segment_template is None:
                        segment_template = adaptation_set.find("SegmentTemplate")
                    if segment_template is None:
                        ValueError
                        log.exit(
                            "Couldn't find a SegmentTemplate for a Representation."
                        )
                    segment_template = copy(segment_template)

                    # join value with base url
                    for item in ("initialization", "media"):
                        if not segment_template.get(item):
                            continue
                        segment_template.set(
                            item,
                            segment_template.get(item).replace(
                                "$RepresentationID$", rep.get("id")
                            ),
                        )
                        query = urllib.parse.urlparse(url).query
                        if (
                            query
                            and not urllib.parse.urlparse(
                                segment_template.get(item)
                            ).query
                        ):
                            segment_template.set(
                                item, segment_template.get(item) + "?" + query
                            )
                        if not re.match(
                            "^https?://", segment_template.get(item).lower()
                        ):
                            segment_template.set(
                                item,
                                urllib.parse.urljoin(
                                    period_base_url
                                    if not rep_base_url
                                    else rep_base_url,
                                    segment_template.get(item),
                                ),
                            )

                    period_duration = period.get("duration")
                    if period_duration:
                        period_duration = Tracks.pt_to_sec(period_duration)
                    mpd_duration = root.get("mediaPresentationDuration")
                    if mpd_duration:
                        mpd_duration = Tracks.pt_to_sec(mpd_duration)

                    track_url = []

                    def replace_fields(url: str, **kwargs: Any) -> str:
                        for field, value in kwargs.items():
                            url = url.replace(f"${field}$", str(value))
                            m = re.search(
                                rf"\${re.escape(field)}%([a-z0-9]+)\$", url, flags=re.I
                            )
                            if m:
                                url = url.replace(m.group(), f"{value:{m.group(1)}}")
                        return url

                    try:
                        NewBaseURL = (
                            re.findall(r"<BaseURL>.+?</BaseURL>", data)[0]
                            .replace("<BaseURL>", "")
                            .replace("</BaseURL>", "")
                        )
                    except IndexError:
                        pass

                    initialization = segment_template.get("initialization")
                    if initialization:
                        # header/init segment
                        track_url.append(
                            replace_fields(
                                initialization,
                                Bandwidth=rep.get("bandwidth"),
                                RepresentationID=rep.get("id"),
                            )
                        )

                    if source == "VTMGO" or source == "STRZ":
                        OldBaseURL = (
                            re.findall(r"https://.+?/p/", track_url[0])[0]
                            .replace("<BaseURL>", "")
                            .replace("</BaseURL>", "")
                        )
                        track_url[0] = track_url[0].replace(OldBaseURL, NewBaseURL)

                    start_number = int(segment_template.get("startNumber") or 1)

                    segment_timeline = segment_template.find("SegmentTimeline")
                    if segment_timeline is not None:
                        seg_time_list = []
                        current_time = 0
                        for s in segment_timeline.findall("S"):
                            if s.get("t"):
                                current_time = int(s.get("t"))
                            for _ in range(1 + (int(s.get("r") or 0))):
                                seg_time_list.append(current_time)
                                current_time += int(s.get("d"))
                        seg_num_list = list(
                            range(start_number, len(seg_time_list) + start_number)
                        )
                        track_url += [
                            replace_fields(
                                segment_template.get("media").replace(
                                    OldBaseURL, NewBaseURL
                                )
                                if OldBaseURL
                                else segment_template.get("media"),
                                Bandwidth=rep.get("bandwidth"),
                                Number=n,
                                RepresentationID=rep.get("id"),
                                Time=t,
                            )
                            for t, n in zip(seg_time_list, seg_num_list)
                        ]
                    else:
                        period_duration = period_duration or mpd_duration
                        segment_duration = float(
                            segment_template.get("duration")
                        ) / float(segment_template.get("timescale") or 1)
                        total_segments = math.ceil(period_duration / segment_duration)
                        track_url += [
                            replace_fields(
                                segment_template.get("media").replace(
                                    OldBaseURL, NewBaseURL
                                )
                                if OldBaseURL
                                else segment_template.get("media"),
                                Bandwidth=rep.get("bandwidth"),
                                Number=s,
                                RepresentationID=rep.get("id"),
                                Time=s,
                            )
                            for s in range(start_number, start_number + total_segments)
                        ]

                if content_type == "video":
                    tracks.append(
                        VideoTrack(
                            id_=None,  # Will be added later on
                            source=source,
                            url=track_url,
                            # metadata
                            codec=(codecs or "").split(".")[0],
                            language=track_lang,
                            is_original_lang=not track_lang
                            or not lang
                            or is_close_match(track_lang, [lang]),
                            duration=Tracks.pt_to_sec(period.get("duration"))
                            if period.get("duration")
                            else 0,
                            bitrate=rep.get("bandwidth"),
                            width=int(rep.get("width") or 0)
                            or adaptation_set.get("width"),
                            height=int(rep.get("height") or 0)
                            or adaptation_set.get("height"),
                            fps=rep.get("frameRate") or adaptation_set.get("frameRate"),
                            hdr10=any(
                                x.get("schemeIdUri") == "http://dashif.org/metadata/hdr"
                                and x.get("value") == "SMPTE2094-40"  # HDR10+
                                for x in adaptation_set.findall("SupplementalProperty")
                            )
                            or all(
                                [
                                    any(
                                        x.get("schemeIdUri")
                                        == "urn:mpeg:mpegB:cicp:ColourPrimaries"
                                        and x.get("value") == "9"  # BT.2020
                                        for x in adaptation_set.findall(
                                            "SupplementalProperty"
                                        )
                                    ),
                                    any(
                                        x.get("schemeIdUri")
                                        == "urn:mpeg:mpegB:cicp:TransferCharacteristics"
                                        and x.get("value") == "16"  # PQ
                                        for x in adaptation_set.findall(
                                            "SupplementalProperty"
                                        )
                                    ),
                                    any(
                                        x.get("schemeIdUri")
                                        == "urn:mpeg:mpegB:cicp:MatrixCoefficients"
                                        and x.get("value") == "9"  # BT.2020
                                        for x in adaptation_set.findall(
                                            "SupplementalProperty"
                                        )
                                    ),
                                ]
                            ),
                            hlg=all(
                                [
                                    any(
                                        x.get("schemeIdUri")
                                        == "urn:mpeg:mpegB:cicp:ColourPrimaries"
                                        and x.get("value") == "9"  # BT.2020
                                        for x in adaptation_set.findall(
                                            "SupplementalProperty"
                                        )
                                    ),
                                    any(
                                        x.get("schemeIdUri")
                                        == "urn:mpeg:mpegB:cicp:TransferCharacteristics"
                                        and x.get("value") == "18"  # HLG
                                        for x in adaptation_set.findall(
                                            "SupplementalProperty"
                                        )
                                    ),
                                    any(
                                        x.get("schemeIdUri")
                                        == "urn:mpeg:mpegB:cicp:MatrixCoefficients"
                                        and x.get("value") == "9"  # BT.2020
                                        for x in adaptation_set.findall(
                                            "SupplementalProperty"
                                        )
                                    ),
                                ]
                            ),
                            dv=codecs and codecs.startswith(("dvhe", "dvh1")),
                            # switches/options
                            descriptor=Track.Descriptor.MPD,
                            # decryption
                            encrypted=encrypted,
                            pssh=pssh,
                            pssh_b64=pssh_b64,
                            kid=kid,
                            # extra
                            extra=(rep, adaptation_set),
                        )
                    )
                elif content_type == "audio":
                    atmos = all(
                        [
                            any(
                                x.get("schemeIdUri")
                                == "tag:dolby.com,2018:dash:EC3_ExtensionType:2018"
                                and x.get("value") == "JOC"  # Joint Object Coding
                                for x in rep.findall("SupplementalProperty")
                            ),
                            any(
                                x.get("schemeIdUri")
                                == "tag:dolby.com,2018:dash:EC3_ExtensionComplexityIndex:2018"
                                and x.get("value") == "16"  # Atmos
                                for x in rep.findall("SupplementalProperty")
                            ),
                        ]
                    ) or all(
                        [
                            any(
                                x.get("schemeIdUri")
                                == "tag:dolby.com,2018:dash:EC3_ExtensionType:2018"
                                and x.get("value") == "JOC"  # Joint Object Coding
                                for x in adaptation_set.findall("SupplementalProperty")
                            ),
                            any(
                                x.get("schemeIdUri")
                                == "tag:dolby.com,2018:dash:EC3_ExtensionComplexityIndex:2018"
                                and x.get("value") == "16"  # Atmos
                                for x in adaptation_set.findall("SupplementalProperty")
                            ),
                        ]
                    )
                    tracks.append(
                        AudioTrack(
                            id_=None,  # Will be added later on
                            source=source,
                            url=track_url,
                            # metadata
                            atmos=atmos,
                            codec=(codecs or "").split(".")[0],
                            language=track_lang,
                            is_original_lang=not track_lang
                            or not lang
                            or is_close_match(track_lang, [lang]),
                            bitrate=rep.get("bandwidth"),
                            channels="16/JOC"
                            if atmos
                            else next(
                                iter(
                                    rep.xpath("AudioChannelConfiguration/@value")
                                    or adaptation_set.xpath(
                                        "AudioChannelConfiguration/@value"
                                    )
                                ),
                                None,
                            ),
                            descriptive=any(
                                x.get("schemeIdUri") == "urn:mpeg:dash:role:2011"
                                and x.get("value") == "description"
                                for x in adaptation_set.findall("Accessibility")
                            ),
                            # switches/options
                            descriptor=Track.Descriptor.MPD,
                            # decryption
                            encrypted=encrypted,
                            pssh=pssh,
                            pssh_b64=pssh_b64,
                            kid=kid,
                            # extra
                            extra=(rep, adaptation_set),
                        )
                    )
                elif content_type == "text":
                    _type = None
                    for role in adaptation_set.findall("Role"):
                        if role.attrib.get("schemeIdUri") == "urn:mpeg:dash:role:2011":
                            value = role.attrib.get("value")
                            if value == "caption":
                                _type = "sdh"
                            elif value in ("forced-subtitle", "forced_subtitle"):
                                _type = "forced"
                            break
                    tracks.append(
                        TextTrack(
                            id_=None,  # Will be added later on
                            source=source,
                            url=track_url,
                            # metadata
                            codec=(
                                codecs or rep.attrib.get("mimeType").split("/")[1] or ""
                            ).split(".")[0],
                            language=track_lang,
                            is_original_lang=not track_lang
                            or not lang
                            or is_close_match(track_lang, [lang]),
                            sdh=bool(_type == "sdh"),
                            forced=bool(_type == "forced"),
                            # switches/options
                            descriptor=Track.Descriptor.MPD,
                            # extra
                            extra=(rep, adaptation_set),
                        )
                    )

    for track in tracks:
        # for some reason it's incredibly common for services to not provide
        # a good and actually unique track ID, sometimes because of the lang
        # dialect not being represented in the id, or the bitrate, or such.
        # this combines all of them as one and hashes it to keep it small(ish).
        track.id = md5(
            "{codec}-{lang}-{bitrate}-{base_url}-{extra}-{flag}".format(
                codec=track.codec,
                lang=track.language,
                bitrate=getattr(track, "bitrate", 0),  # subs may not state bandwidth
                base_url=(track.extra[0].findtext("BaseURL") or "").split("?")[0],
                extra=(track.extra[1].get("audioTrackId") or "")
                + (track.extra[0].get("id") or ""),
                flag=track.variables.get("flag") or "",
            ).encode()
        ).hexdigest()

    # Add tracks, but warn only. Assume any duplicate track cannot be handled.
    # Since the custom track id above uses all kinds of data, there realistically would
    # be no other workaround.
    tracks_obj = Tracks()
    tracks_obj.add(tracks)

    return tracks_obj
