import re
import os
import unicodedata
import glob

from pathlib import Path
from titlecase import titlecase
from enum import Enum
from typing import Any, Iterator, Optional, Union
from langcodes import Language
from unidecode import unidecode
from widevinely.utils import logger
from widevinely import config
from widevinely.objects.tracks import Tracks

log = logger.getLogger("titles")

VIDEO_CODEC_MAP = {"AVC": "H.264", "HEVC": "H.265"}
DYNAMIC_RANGE_MAP = {
    "HDR10": "HDR",
    "HDR10+": "HDR",
    "HDR10 / HDR10+": "HDR",
    "Dolby Vision": "DV",
}
AUDIO_CODEC_MAP = {"E-AC-3": "DDP", "AC-3": "DD"}


class Title:
    def __init__(
        self,
        id_: str,
        type_: "Title.Types",
        name: Optional[str] = None,
        year: Optional[int] = None,
        release_date: Optional[str] = None,
        season: Optional[int] = None,
        episode: Optional[int] = None,
        episode_name: Optional[str] = None,
        episode_synopsis: Optional[str] = None,
        original_lang: Optional[Union[str, Language]] = None,
        source: Optional[str] = None,
        service_data: Optional[Any] = None,
        tracks: Optional[Tracks] = None,
        filename: Optional[str] = None,
        tmdb_id: Optional[int] = None,
        imdb_id: Optional[str] = None,
        tvdb_id: Optional[int] = None,
        synopsis: Optional[str] = None,
        thumbnail: Optional[str] = None,
    ) -> None:
        self.id = id_
        self.type = type_
        self.name = name
        self.synopsis = synopsis
        self.thumbnail = thumbnail
        self.year = year
        self.release_date = release_date
        self.season = int(season or 0)
        self.episode = int(episode or 0)
        self.episode_name = episode_name
        self.episode_synopsis = episode_synopsis
        self.tmdb_id = int(tmdb_id or 0)
        self.imdb_id = imdb_id
        self.tvdb_id = tvdb_id
        self.original_lang = Language.get(original_lang) if original_lang else None
        self.source = source
        self.service_data: Any = service_data or {}
        self.tracks = tracks or Tracks()
        self.filename = filename

        if not self.filename:
            # auto generated initial filename
            self.filename = self.parse_filename()

    def parse_filename(self, *service, media_info=None, folder=False):
        if media_info:
            video_track = next(iter(media_info.video_tracks), None)
            if config.config.output_template.get("use_last_audio", False):
                audio_track = next(iter(reversed(media_info.audio_tracks)), None)
            else:
                audio_track = next(iter(media_info.audio_tracks), None)
        else:
            video_track = None
            audio_track = None

        self.name = titlecase(unidecode(self.name))
        if self.tracks.videos and not video_track:
            self.resolution = f"{self.tracks.videos[0].resolution}p"

        # create the initial filename string
        facets = ""
        if video_track:
            if any(x.imax_enhanced for x in self.tracks.videos):
                facets = "IMAX"
            elif any(x.original_aspect_ratio for x in self.tracks.videos):
                facets = "OAR"
            quality = self.tracks.videos[0].resolution
        else:
            quality = ""

        if audio_track:
            audio = f"{AUDIO_CODEC_MAP.get(audio_track.format) or audio_track.format}"
            audio += f"{float(sum({'LFE': 0.1}.get(x, 1) for x in audio_track.channel_layout.split(' '))):.1f} "
            if (
                audio_track.format_additionalfeatures
                and "JOC" in audio_track.format_additionalfeatures
            ):
                audio += "Atmos "
        else:
            audio = ""

        video = ""
        if video_track:
            if (video_track.hdr_format_profile or "").startswith("dvhe.08"):
                video += "HDR.DV "
            elif (video_track.hdr_format or "").startswith("Dolby Vision"):
                video += "DV "
            elif video_track.hdr_format_commercial:
                video += f"{DYNAMIC_RANGE_MAP.get(video_track.hdr_format_commercial)} "
            elif "HLG" in (video_track.transfer_characteristics or "") or "HLG" in (
                video_track.transfer_characteristics_original or ""
            ):
                video += "HLG "
            if float(video_track.frame_rate) > 30 and self.source != "iP":
                video += "HFR "
            video += (
                video_track.encoded_library_name
                or f"{VIDEO_CODEC_MAP.get(video_track.format) or video_track.format}"
            )

        tag = config.config.tag
        if quality and quality <= 576:
            tag = config.config.tag_sd or tag

        if self.type == Title.Types.MOVIE:
            filename = config.config.output_template["movies"].format(
                title=self.name,
                year=self.year or "",
                facets=facets or "",
                quality=f"{quality}p" if quality else "",
                source=self.source,
                audio=audio,
                video=video,
                tag=tag,
            )
        elif (
            self.type == Title.Types.MOVIE_TRAILER
            or self.type == Title.Types.TV_TRAILER
        ):
            return (
                f"{self.name}{f' ({self.year})' if self.year else ''} [trailer]-trailer"
            )
        else:
            episode_name = self.episode_name
            # TODO: Maybe we should only strip these if all episodes have such names.
            if re.fullmatch(
                r"(?:Episode|Aflevering|Afl.|Chapter|Capitulo|Folge) \d+",
                episode_name or "",
            ):
                episode_name = None

            filename = config.config.output_template["series"].format(
                title=self.name,
                season_episode=(
                    f"S{self.season:02}"
                    + (
                        f"E{self.episode:02}"
                        if (self.episode is not None and not folder)
                        else ""
                    )
                ),
                episode_name=(episode_name or "") if not folder else "",
                facets=facets or "",
                quality=f"{quality}p" if quality else "",
                source=self.source,
                audio=audio,
                video=video,
                tag=tag,
            )

        filename = re.sub(r"\s+", "." if "." in filename else " ", filename)
        filename = re.sub(r"\.\.+", "." if "." in filename else " ", filename)
        if not config.config.tag:
            filename = filename.replace("-None", "")
        else:
            filename = re.sub(
                rf"\.+(-{re.escape(config.config.tag)})$", r"\1", filename
            ).encode("UTF-8")

        filename = (
            filename.rstrip().rstrip(".")
            if isinstance(filename, str)
            else filename.decode("UTF-8").rstrip().rstrip(".")
        )  # remove whitespace and last right-sided . if needed

        filename = self.normalize_filename(filename)
        return filename

    @staticmethod
    def normalize_filename(filename, space=False):
        # replace all non-ASCII characters with ASCII equivalents
        filename = unidecode(filename)
        filename = "".join(c for c in filename if unicodedata.category(c) != "Mn")

        # remove or replace further characters as needed
        filename = filename.replace(
            "/", " - " if not space else " "
        )  # e.g. amazon multi-episode titles
        filename = re.sub(
            r"[:; ]" if not space else r"[:;]", ".", filename
        )  # structural chars to .
        filename = re.sub(r"[\\*!?¿,'\"<>|$#]", "", filename)  # unwanted chars
        if "." in filename:
            filename = re.sub(r"[()]", "", filename)  # unwanted
        filename = re.sub(
            r"[. ]{2,}", "." if not space else " ", filename
        )  # replace 2+ neighbour dots and spaces with .
        return filename.replace(".-.", "." if not space else "")

    def normalize_foldername(foldername) -> str:
        # replace all non-ASCII characters with ASCII equivalents
        foldername = unidecode(foldername)
        foldername = "".join(c for c in foldername if unicodedata.category(c) != "Mn")

        # remove or replace further characters as needed
        foldername = foldername.replace("/", " - ")  # e.g. amazon multi-episode titles
        foldername = re.sub(r"[:; ]", " ", foldername)  # structural chars to .
        foldername = re.sub(r"[\\*!?¿,'\"()<>|$#]", "", foldername)  # unwanted chars
        foldername = re.sub(
            r"[. ]{2,}", " - ", foldername
        )  # replace 2+ neighbour dots and spaces with .

        return foldername

    def is_wanted(self, wanted: list) -> bool:
        if self.type != Title.Types.TV or not wanted:
            return True
        return f"{self.season}x{self.episode}" in wanted

    class Types(Enum):
        MOVIE = 1
        MOVIE_TRAILER = 2
        TV = 3
        TV_TRAILER = 4


class Titles(list):
    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.title_name = None

        if self:
            self.title_name = self[0].name

    def print(self, service, total, wanted):
        type_ = self[0].type.name
        log.info_(
            f" - [content]TITLE_TYPE[/content]   {'TRAILER' if 'TRAILER' in type_ else 'SHOW' if 'TV' in type_ else 'COLLECTION' if 'collection' in service.title else 'MOVIE'}"
        )
        log.info_(
            f" - [content]TITLE_NAME[/content]   {service.collection_title}"
            if "collection" in service.title
            else f" - [content]TITLE_NAME[/content]   {self.title_name} {f'({self[0].year})' if self[0].year else ''}"
        )
        if "TV" in type_:
            specials = len([x for x in self if not x.episode])
            selected_specials = len([x for x in wanted if not x.episode])
            selected_seasons = set(
                [
                    str(season)
                    for season in [
                        episode.season for episode in wanted if episode.season
                    ]
                ]
            )
            selected_episodes = [episode for episode in [episode for episode in wanted]]

            if "TRAILER" not in type_:
                log.info_(
                    f" - [content]SEASONS[/content]      [dim]AVAILABLE[/dim] {str(total[0]).rjust(len(str(total[1])))} [dim]WANTED[/dim] {'ALL SEASONS' if total[0] == len(selected_seasons) and total[0] > 1 else f'S{wanted[0].season:02d}' if len(selected_seasons) == 1 else ', '.join(sorted(selected_seasons))}"
                )
                log.info_(
                    f" - [content]EPISODES[/content]     [dim]AVAILABLE[/dim] {total[1]} [dim]WANTED[/dim] {'ALL EPISODES' if total[1] == len(selected_episodes) and len(self) > 1 else f'E{wanted[0].episode:02d}' if len(selected_episodes) == 1 else len(selected_episodes)}"
                )

                if specials:
                    log.info_(
                        f" - [content]SPECIALS[/content]     [dim]AVAILABLE[/dim] {specials} [dim]WANTED[/dim] {selected_specials}"
                    )

    def existance_check(self, args, directories, service, title, files=[]):
        service = service.lower().replace("prime video", "amazon")
        title_name = Title.normalize_foldername(title.name)
        if os.path.exists(directories.downloads):
            directories_downloads = (
                directories.downloads.parent
                if str(directories.downloads).endswith(service)
                else directories.downloads
            )

            files = [
                f"{Path(file).name if title_name not in directories.downloads.name else file}"
                for file in glob.glob(
                    str(
                        (
                            directories_downloads
                            if title_name not in directories.downloads.name
                            else directories.downloads.parent
                        )
                        / "**"
                        / "*.*"
                    ),
                    recursive=True,
                )
                if (
                    title_name
                    if "TRAILER" in title.type.name
                    else f"{title_name.replace(' ', '.')}.S{title.season:02d}E{title.episode:02d}"
                    if title.type == Title.Types.TV
                    else f"{title_name.replace(' ', '.')}.{title.year}"
                    if title.year
                    else title_name.replace(" ", ".")
                )
                in file
            ]

            download_name = (
                f"{title.name} S{title.season:02d}E{title.episode:02d}"
                if title.type == Title.Types.TV
                else f"{title.name} ({title.year})"
                if title.year
                else title.name
            )

            if "TRAILER" in title.type.name:
                download_name = "Trailer: " + download_name

            log.info_(f"\n{download_name.upper()}", style="title")
            if (
                args.dl.video_only
                or args.dl.audio_only
                or args.dl.subs_only
                or args.dl.ignore_existance
            ):
                return False

            if "TRAILER" in title.type.name:
                if any("[trailer]-trailer" in x for x in files):
                    log.warning_(" - Trailer already exists for this title")
                    return True
                return False

            files = [
                file
                for file in files
                if (
                    "WEB-DL.DUAL." in file
                    if files and len(title.tracks.audio) == 2
                    else "WEB-DL.MUTLI." in file
                    if files and len(title.tracks.audio) >= 3
                    else "WEB-DL.DUAL." not in file and "WEB-DL.MUTLI." not in file
                )
            ]

            if files:
                files = [file for file in files if title.resolution in file]

            if files:
                files = [
                    file
                    for file in files
                    if title.tracks.videos[0].variables["codec"].lower()
                    in file.lower().replace("x264", "h.264")
                ]

            if files:
                if len(title.tracks.videos) == 2:
                    # In this case it should always be an HDR10 and DV track
                    files = [file for file in files if ".hdr-dv." in file.lower()]
                elif title.tracks.videos[0].variables["range"] != "SDR":
                    # Filenames never contain SDR
                    files = [
                        file
                        for file in files
                        if f".{title.tracks.videos[0].variables['range'].lower().replace('hdr10', 'hdr').replace('hdr10+', 'hdr')}."
                        in file.lower()
                        and ".hdr-dv." not in file.lower()
                    ]

            if not files:
                return False

            if files:
                log.warning_("File already exists for this title.")
                return True

        return False

    def order(self):
        """This will order the Titles to be oldest first."""
        self.sort(key=lambda t: int(t.year or 0))
        self.sort(key=lambda t: int(t.episode or 0))
        self.sort(key=lambda t: int(t.season or 0))

    def with_wanted(self, wanted: list) -> Iterator[Title]:
        """Yield only wanted tracks."""
        for title in self:
            if title.is_wanted(wanted):
                yield title
