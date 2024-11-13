import re

from hashlib import md5
from widevinely.objects import AudioTrack, TextTrack, Track, Tracks, VideoTrack
from widevinely.utils import is_close_match, logger
from pywidevinely import PSSH

log = logger.getLogger("m3u8.parser")


def parse(master, lang=None, source=None):
    """
    Convert a Variant Playlist M3U8 document to a Tracks object with Video, Audio and
    Subtitle Track objects. This is not an M3U8 parser, use https://github.com/globocom/m3u8
    to parse, and then feed the parsed M3U8 object.

    :param master: M3U8 object of the `m3u8` project: https://github.com/globocom/m3u8
    :param lang: Preferably the original-recorded language of the content in ISO alpha 2 format.
        It will be used as a fallback if a track has no language, and for metadata like if
        the track should be a default track.
    :param source: Source tag for the returned tracks.

    The resulting Track objects' URL will be to another M3U8 file, but this time to an
    actual media stream and not to a variant playlist. The m3u8 downloader code will take
    care of that, as the tracks downloader will be set to `M3U8`.

    Don't forget to manually handle the addition of any needed or extra information or values.
    Like `encrypted`, `pssh`, `hdr10`, `dv`, e.t.c. Essentially anything that is per-service
    should be looked at. Some of these values like `pssh` and `dv` will try to be set automatically
    if possible but if you definitely have the values in the service, then set them.
    Subtitle Codec will default to vtt as it has no codec information.

    Example:
        tracks = Tracks.from_m3u8(m3u8.load(url), lang="en")
        # check the m3u8 project for more info and ways to parse m3u8 documents
    """
    VideoTracks, AudioTracks, TextTracks = (
        [],
        [],
        [],
    )  # Will not clean before next title when adding to def

    if not master.is_variant:
        ValueError
        log.exit("Tracks.from_m3u8: Expected a Variant Playlist M3U8 document...")

    # VIDEO
    for x, y in zip(master.data["playlists"], master.playlists):
        pssh = None
        pssh_b64 = None
        fallback_pssh = None
        characteristic = None
        if x["stream_info"].get("characteristics"):
            characteristic = x["stream_info"]["characteristics"].replace('"', "")
            session_keys = [
                (x._extra_params.get("characteristics"), x)
                for x in master.session_keys
                if x.keyformat.lower()
                == "urn:uuid:edef8ba9-79d6-4ace-a3c8-27dcd51d21ed"
            ]

            for session_key in session_keys:
                if characteristic in session_key[0] and "," in session_key[0]:
                    pssh_b64 = session_key[1].uri.split(",")[-1]
                    pssh = PSSH(pssh_b64)

            for session_key in session_keys:
                if session_key[0] == characteristic:
                    if not pssh_b64:
                        pssh_b64 = session_key[1].uri.split(",")[-1]
                        pssh = PSSH(pssh_b64)
                    else:
                        fallback_pssh = PSSH(session_key[1].uri.split(",")[-1])

        VideoTrack_ = [
            VideoTrack(
                id_=md5(str(y).encode()).hexdigest()[
                    0:7
                ],  # 7 chars only for filename length
                source=source,
                url=("" if re.match("^https?://", y.uri) else y.base_uri) + y.uri,
                # metadata
                codec=[
                    x
                    for x in re.split(",", y.stream_info.codecs)
                    if x[:3] in ["avc", "hvc", "hev", "dvh"]
                ][0][:4],
                language=lang,  # playlists don't state the language, fallback must be used
                is_original_lang=bool(
                    lang
                ),  # TODO: All that can be done is assume yes if lang is provided
                duration=None,
                bitrate=y.stream_info.average_bandwidth or y.stream_info.bandwidth,
                width=y.stream_info.resolution[0],
                height=y.stream_info.resolution[1],
                fps=y.stream_info.frame_rate,
                hdr10=(
                    y.stream_info.codecs.split(".")[0] not in ("dvhe", "dvh1")
                    and (y.stream_info.video_range or "SDR").strip('"') != "SDR"
                ),
                hlg=False,  # TODO: Can we get this from the manifest?
                dv=y.stream_info.codecs.split(".")[0] in ("dvhe", "dvh1"),
                # switches/options
                descriptor=Track.Descriptor.M3U,
                # decryption
                encrypted=True,  # TODO: automatically detect HLS encryption
                pssh=pssh,
                pssh_b64=pssh_b64,
                fallback_pssh=fallback_pssh,
                # extra
                extra=y,
            )
        ]
        VideoTracks.extend(VideoTrack_)

    # AUDIO
    for x in master.media:
        pssh = None
        pssh_b64 = None
        fallback_pssh = None
        characteristic = None
        if x.type == "AUDIO" and x.uri:
            if x.characteristics:
                characteristic = x.characteristics.replace('"', "")
                session_keys = [
                    (x._extra_params.get("characteristics"), x)
                    for x in master.session_keys
                    if x.keyformat.lower()
                    == "urn:uuid:edef8ba9-79d6-4ace-a3c8-27dcd51d21ed"
                ]

                for session_key in session_keys:
                    if characteristic in session_key[0] and "," in session_key[0]:
                        pssh_b64 = session_key[1].uri.split(",")[-1]
                        pssh = PSSH(pssh_b64)

                for session_key in session_keys:
                    if session_key[0] == characteristic:
                        if not pssh_b64:
                            pssh_b64 = session_key[1].uri.split(",")[-1]
                            pssh = PSSH(pssh_b64)
                        else:
                            fallback_pssh = PSSH(session_key[1].uri.split(",")[-1])

            AudioTrack_ = [
                AudioTrack(
                    id_=md5(str(x).encode()).hexdigest()[0:6],
                    source=source,
                    url=("" if re.match("^https?://", x.uri) else x.base_uri) + x.uri,
                    # metadata
                    codec=[
                        x
                        for x in re.split(",", y.stream_info.codecs)
                        if x[:3] not in ["avc", "hvc", "hev", "dvh"]
                    ][0].split(".")[0],
                    language=x.language,
                    is_original_lang=lang and is_close_match(x.language, [lang]),
                    bitrate=0,  # TODO: M3U doesn't seem to state bitrate?
                    channels=x.channels,
                    atmos=bool(x.channels == "16/JOC"),
                    descriptive="public.accessibility.describes-video"
                    in (x.characteristics or ""),
                    # switches/options
                    descriptor=Track.Descriptor.M3U,
                    # decryption
                    encrypted=False,  # don't know for sure if encrypted
                    pssh=pssh,
                    pssh_b64=pssh_b64,
                    fallback_pssh=fallback_pssh,
                    # extra
                    extra=x,
                )
            ]
            AudioTracks.extend(AudioTrack_)

    # SUBTITLES
    for x in master.media:
        if x.type == "SUBTITLES":
            TextTrack_ = [
                TextTrack(
                    id_=md5(str(x).encode()).hexdigest()[0:6],
                    source=source,
                    url=("" if re.match("^https?://", x.uri) else x.base_uri) + x.uri,
                    # metadata
                    codec="vtt",  # assuming VTT, codec info isn't shown
                    language=x.language,
                    is_original_lang=lang and is_close_match(x.language, [lang]),
                    forced=x.forced == "YES",
                    sdh="public.accessibility.describes-music-and-sound"
                    in (x.characteristics or ""),
                    # switches/options
                    descriptor=Track.Descriptor.M3U,
                    # extra
                    extra=x,
                )
            ]
            TextTracks.extend(TextTrack_)

    return Tracks(VideoTracks, AudioTracks, TextTracks)
