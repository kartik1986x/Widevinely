import os
import sqlite3
import pymysql

from enum import Enum
from typing import Optional
from widevinely.utils import logger
from widevinely.utils.AtomicSQL import AtomicSQL
from widevinely.objects import Title, VideoTrack, AudioTrack

log = logger.getLogger("vaults")


class InsertResult(Enum):
    FAILURE = 0
    SUCCESS = 1
    ALREADY_EXISTS = 2


class Vault:
    """
    Key Vault.
    This defines various details about the vault, including its Connection object.
    """

    def __init__(
        self,
        type_,
        name,
        ticket=None,
        path=None,
        username=None,
        password=None,
        database=None,
        host=None,
    ):
        from widevinely.config import directories

        try:
            self.type = self.Types[type_.upper()]
        except KeyError:
            ValueError
            log.exit(f"Invalid vault type [{type_}]")
        self.name = name
        self.con = None
        if self.type == Vault.Types.LOCAL:
            if not path:
                ValueError
                log.exit("Local vault has no path specified")
            self.con = sqlite3.connect(
                os.path.expanduser(path).format(data_dir=directories.data)
            )
        elif self.type == Vault.Types.REMOTE:
            self.con = pymysql.connect(
                user=username,
                password=password or "",
                db=database,
                host=host,
                cursorclass=pymysql.cursors.DictCursor,  # TODO: Needed? Maybe use it on sqlite3 too?
            )
        else:
            ValueError
            log.exit(f"Invalid vault type [{self.type.name}]")
        self.ph = {self.Types.LOCAL: "?", self.Types.REMOTE: "%s"}[self.type]
        self.ticket = ticket

        self.perms = self.get_permissions()
        if not self.has_permission("SELECT"):
            ValueError
            log.exit(f"Cannot use vault. Vault {self.name} has no SELECT permission.")

    def __str__(self):
        return f"{self.name} ({self.type.name})"

    def get_permissions(self):
        if self.type == self.Types.LOCAL:
            return [tuple([["*"], tuple(["*", "*"])])]

        with self.con.cursor() as c:
            c.execute("SHOW GRANTS")
            grants = c.fetchall()
            grants = [next(iter(x.values())) for x in grants]
        grants = [tuple(x[6:].split(" TO ")[0].split(" ON ")) for x in list(grants)]
        grants = [
            (
                list(map(str.strip, perms.replace("ALL PRIVILEGES", "*").split(","))),
                location.replace("`", "").split("."),
            )
            for perms, location in grants
        ]

        return grants

    def has_permission(self, operation, database=None, table=None):
        grants = [x for x in self.perms if x[0] == ["*"] or operation.upper() in x[0]]
        if grants and database:
            grants = [x for x in grants if x[1][0] in (database, "*")]
        if grants and table:
            grants = [x for x in grants if x[1][1] in (table, "*")]
        return bool(grants)

    class Types(Enum):
        LOCAL = 1
        REMOTE = 2


class Vaults:
    """
    Key Vaults.
    Keeps hold of Vault objects, with convenience functions for
    using multiple vaults in one actions, e.g. searching vaults
    for a key based on kid.
    This object uses AtomicSQL for accessing the vault connections
    instead of directly. This is to provide thread safety but isn't
    strictly necessary.
    """

    def __init__(self, vaults, service, key_policy):
        self.adb = AtomicSQL()
        self.vaults = sorted(
            vaults, key=lambda v: 0 if v.type == Vault.Types.LOCAL else 1
        )
        self.service = service
        self.key_policy = key_policy
        for vault in self.vaults:
            vault.ticket = self.adb.load(vault.con)
            self.create_table(vault, commit=True)

    def __iter__(self):
        return iter(self.vaults)

    def get(self, title, track) -> tuple[Optional[str], Optional[Vault]]:
        for vault in self.vaults:
            # Note on why it matches by KID instead of PSSH:
            # Matching cache by pssh is not efficient. The PSSH can be made differently by all different
            # clients for all different reasons, e.g. only having the init data, but the cached PSSH is
            # a manually crafted PSSH, which may not match other clients manually crafted PSSH, and such.
            # So it searches by KID instead for this reason, as the KID has no possibility of being different
            # client to client other than capitalization. There is an unknown with KID matching, It's unknown
            # for *sure* if the KIDs ever conflict or not with another bitrate/stream/title. I haven't seen
            # this happen ever and neither has anyone I have asked.
            if not self.table_exists(vault, self.service):
                continue  # this service has no service table, so no keys, just skip
            if not vault.ticket:
                ValueError
                log.exit(f"Vault {vault.name} does not have a valid ticket available.")

            c = self.adb.safe_execute(
                vault.ticket,
                lambda db, cursor: cursor.execute(
                    "SELECT `key` FROM `{1}` WHERE `kid`={0}".format(
                        vault.ph, self.service
                    ),
                    [track.kid],
                ),
            ).fetchone()
            if c:
                if isinstance(c, dict):
                    c = list(c.values())
                return c[0], vault
        return None, None

    def add_missing(self, title, track, commit: bool = False):
        kind, title_name, type_, resolution, range_, profile = self.get_key_attributes(
            title, track, track.kid
        )
        for vault in self.vaults:
            if vault.type == Vault.Types.REMOTE:
                self.ping(vault.con)
            c = self.adb.safe_execute(
                vault.ticket,
                lambda db, cursor: cursor.execute(
                    "SELECT `kind`, `id`, `title`, `key`, `type`, `resolution`, `range`, `profile` FROM `{1}` WHERE `kid`={0}".format(
                        vault.ph, self.service
                    ),
                    [track.kid],
                ),
            ).fetchone()
            if c:
                if isinstance(c, dict):
                    c = list(c.values())
                if vault.has_permission("UPDATE", table=self.service):
                    """Add kind when missing in the database"""
                    if not c[0] or c[0] != kind:
                        self.adb.safe_execute(
                            vault.ticket,
                            lambda db, cursor: cursor.execute(
                                "UPDATE `{1}` SET `kind`={0} WHERE `kid`={0}".format(
                                    vault.ph, self.service
                                ),
                                [kind, track.kid],
                            ),
                        )
                    """ Add title.id when missing in the database """
                    if not c[1] or c[1] != title.id:
                        self.adb.safe_execute(
                            vault.ticket,
                            lambda db, cursor: cursor.execute(
                                "UPDATE `{1}` SET `id`={0} WHERE `kid`={0}".format(
                                    vault.ph, self.service
                                ),
                                [title.id, track.kid],
                            ),
                        )
                    """ Add title when missing in the database """
                    if not c[2] or c[2] != title_name:
                        self.adb.safe_execute(
                            vault.ticket,
                            lambda db, cursor: cursor.execute(
                                "UPDATE `{1}` SET `title`={0} WHERE `kid`={0}".format(
                                    vault.ph, self.service
                                ),
                                [title_name, track.kid],
                            ),
                        )
                    """ Add track type when missing or UNKNOWN in the database """
                    if track.encrypted and not c[4]:
                        self.adb.safe_execute(
                            vault.ticket,
                            lambda db, cursor: cursor.execute(
                                "UPDATE `{1}` SET `type`={0} WHERE `kid`={0}".format(
                                    vault.ph, self.service
                                ),
                                [type_, track.kid],
                            ),
                        )
                    """ Add track resolution when missing in the database """
                    if not c[5]:
                        self.adb.safe_execute(
                            vault.ticket,
                            lambda db, cursor: cursor.execute(
                                "UPDATE `{1}` SET `resolution`={0} WHERE `kid`={0}".format(
                                    vault.ph, self.service
                                ),
                                [resolution, track.kid],
                            ),
                        )

                    """ Add track range when missing in the database """
                    if not c[6]:
                        self.adb.safe_execute(
                            vault.ticket,
                            lambda db, cursor: cursor.execute(
                                "UPDATE `{1}` SET `range`={0} WHERE `kid`={0}".format(
                                    vault.ph, self.service
                                ),
                                [range_, track.kid],
                            ),
                        )
                    """ Add track profile when missing in the database """
                    if not c[7]:
                        self.adb.safe_execute(
                            vault.ticket,
                            lambda db, cursor: cursor.execute(
                                "UPDATE `{1}` SET `profile`={0} WHERE `kid`={0}".format(
                                    vault.ph, self.service
                                ),
                                [profile, track.kid],
                            ),
                        )
            if commit:
                self.commit(vault)
        return True

    def update(self, title, track, commit: bool = False):
        for vault in self.vaults:
            (
                kind,
                title_name,
                type_,
                resolution,
                range_,
                profile,
            ) = self.get_key_attributes(title, track, track.kid)
            c = self.adb.safe_execute(
                vault.ticket,
                lambda db, cursor: cursor.execute(
                    "SELECT `kind`, `id`, `title`, `key`, `type`, `resolution`, `range`, `profile` FROM `{1}` WHERE `kid`={0}".format(
                        vault.ph, self.service
                    ),
                    [track.kid],
                ),
            ).fetchone()
            if c:
                if isinstance(c, dict):
                    c = list(c.values())
                """ Change type to VIDEO+AUDIO when kid is same """
                if (
                    isinstance(track, AudioTrack)
                    and track.encrypted
                    and c[4] == "VIDEO"
                ):
                    self.adb.safe_execute(
                        vault.ticket,
                        lambda db, cursor: cursor.execute(
                            "UPDATE `{1}` SET `type`={0} WHERE `kid`={0}".format(
                                vault.ph, self.service
                            ),
                            ["VIDEO | AUDIO", track.kid],
                        ),
                    )
                if isinstance(track, VideoTrack):
                    if c[4] == "AUDIO":
                        self.adb.safe_execute(
                            vault.ticket,
                            lambda db, cursor: cursor.execute(
                                "UPDATE `{1}` SET `type`={0} WHERE `kid`={0}".format(
                                    vault.ph, self.service
                                ),
                                ["VIDEO | AUDIO", track.kid],
                            ),
                        )

                    """ Add track resolution when kid is same as another track resolution """
                    if c[5] not in [resolution, "ALL"]:
                        res_order = {"SD": 0, "HD": 1, "FHD": 3, "UHD": 4}
                        c5 = c[5].split(" | ")
                        c5.append(resolution)
                        c5 = sorted(c5, key=lambda x: res_order[x])
                        if c[0] == "SD" and c[-1] == "UHD":
                            resolution = "ALL"
                        else:
                            resolution = " | ".join(c5) if len(c5) < 4 else "ALL"

                        self.adb.safe_execute(
                            vault.ticket,
                            lambda db, cursor: cursor.execute(
                                "UPDATE `{1}` SET `resolution`={0} WHERE `kid`={0}".format(
                                    vault.ph, self.service
                                ),
                                [resolution, track.kid],
                            ),
                        )

                    """ Add track range when kid is same as another track range """
                    if c[6] not in [range_, "ALL"]:
                        range_order = {"SDR": 0, "HDR10": 1, "HLG": 3, "DV": 4}
                        c6 = c[6].split(" | ")
                        c6.append(range_)
                        for x in c6:
                            if x == "DOLBY_VISION":
                                c6[c6.index(x)] = "DV"
                        c6 = list(
                            dict.fromkeys(sorted(c6, key=lambda x: range_order[x]))
                        )
                        range_ = " | ".join(c6) if len(c6) < 4 else "ALL"

                        if range_ != c[6]:
                            self.adb.safe_execute(
                                vault.ticket,
                                lambda db, cursor: cursor.execute(
                                    "UPDATE `{1}` SET `range`={0} WHERE `kid`={0}".format(
                                        vault.ph, self.service
                                    ),
                                    [range_, track.kid],
                                ),
                            )
            if commit:
                self.commit(vault)
        return True

    def table_exists(self, vault: Vault, table: str) -> bool:
        if vault.type == Vault.Types.REMOTE:
            self.ping(vault.con)
        if not vault.ticket:
            ValueError
            log.exit(f"Vault {vault.name} does not have a valid ticket available.")
        if vault.type == Vault.Types.LOCAL:
            return (
                self.adb.safe_execute(
                    vault.ticket,
                    lambda db, cursor: cursor.execute(
                        f"SELECT count(name) FROM sqlite_master WHERE type='table' AND name={vault.ph}",
                        [table],
                    ),
                ).fetchone()[0]
                == 1
            )
        return (
            list(
                self.adb.safe_execute(
                    vault.ticket,
                    lambda db, cursor: cursor.execute(
                        "SELECT count(TABLE_NAME) FROM information_schema.TABLES WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s",
                        (vault.con.db, table),
                    ),
                )
                .fetchone()
                .values()
            )[0]
            == 1
        )

    def create_table(self, vault, commit=False):
        if self.table_exists(vault, self.service):
            return
        if not vault.ticket:
            ValueError
            log.exit(f"Vault {vault.name} does not have a valid ticket available.")
        if vault.has_permission("CREATE"):
            # log.info_(f"Creating `{table}` table in {vault.name} ({vault.type}) key vault...")
            self.adb.safe_execute(
                vault.ticket,
                lambda db, cursor: cursor.execute(
                    f"""CREATE TABLE `{self.service}` (
                    `uuid`  {'INTEGER NOT NULL UNIQUE' if vault.type == Vault.Types.LOCAL else 'INTEGER AUTO_INCREMENT PRIMARY KEY'},
                    `kind`	TEXT,   
                    `id`	TEXT,
                    `title`	TEXT,
                    `kid`	{"TEXT NOT NULL COLLATE NOCASE" if vault.type == Vault.Types.LOCAL else 'VARCHAR(255) NOT NULL'},
                    `key`	{"TEXT NOT NULL COLLATE NOCASE" if vault.type == Vault.Types.LOCAL else 'VARCHAR(255) NOT NULL'},
                    `type`	TEXT,
                    `resolution` TEXT,
                    `range`	TEXT,
                    `profile`	TEXT,
                    {'PRIMARY KEY("uuid" AUTOINCREMENT),' if vault.type == Vault.Types.LOCAL else ''}
                    UNIQUE(`kid`,`key`)
                );"""
                ),
            )
            if commit:
                self.commit(vault)

    def insert_key(
        self, vault: Vault, title, track, kid, key, commit: bool = False
    ) -> bool:
        if not self.table_exists(vault, self.service):
            return InsertResult.FAILURE
        if not vault.ticket:
            ValueError
            log.exit(f"Vault {vault.name} does not have a valid ticket available.")
        if not vault.has_permission("INSERT", table=self.service):
            ValueError
            log.exit(
                f"Cannot insert key into Vault. Vault {vault.name} has no INSERT permission."
            )

        if self.adb.safe_execute(
            vault.ticket,
            lambda db, cursor: cursor.execute(
                "SELECT `uuid` FROM `{1}` WHERE `kid`={0} AND `key`={0}".format(
                    vault.ph, self.service
                ),
                [kid, key],
            ),
        ).fetchone():
            return InsertResult.ALREADY_EXISTS

        kind, title_name, type_, resolution, range_, profile = self.get_key_attributes(
            title, track, kid
        )

        self.adb.safe_execute(
            vault.ticket,
            lambda db, cursor: cursor.execute(
                f"""INSERT INTO `{self.service}` (
                    `kind`,
                    `id`, 
                    `title`, 
                    `kid`, 
                    `key`, 
                    `type`, 
                    `resolution`, 
                    `range`, 
                    `profile`
                    ) VALUES (
                        "{kind}",
                        "{title.id}", 
                        "{title_name}",
                        "{kid}", 
                        "{key}", 
                        "{type_ if track.encrypted else  ''}", 
                        "{resolution if kid == track.kid else 'SD' if profile else ''}", 
                        "{range_ if kid == track.kid else 'SDR' if profile else ''}", 
                        "{profile}"
                        );"""
            ),
        )
        if commit:
            self.commit(vault)
        return InsertResult.SUCCESS

    def commit(self, vault: Vault) -> None:
        assert vault.ticket is not None
        self.adb.commit(vault.ticket)

    def ping(self, con):
        con.ping(reconnect=True)

    def get_key_attributes(self, title, track, kid):
        if title.type == Title.Types.MOVIE:
            title_name = f"{title.name} ({title.year})" if title.year else title.name
            kind = "Movie"
        elif title.type == Title.Types.TV:
            title_name = f"{title.name} S{title.season:02d}E{title.episode:02d}"
            kind = "Episode"
        elif title.type not in [Title.Types.MOVIE_TRAILER, Title.Types.TV_TRAILER]:
            title_name = "Unkown"
            kind = "Unknown"

        if title.type in [Title.Types.MOVIE_TRAILER, Title.Types.TV_TRAILER]:
            title_name += " [trailer]"
            kind = "Trailer"

        if isinstance(track, VideoTrack):
            if self.key_policy == "ALL":
                resolution = "ALL"
            elif track.height > 1080:
                resolution = "UHD"
            elif track.height <= 1080 and track.height > 720:
                resolution = "FHD"
            elif track.height <= 720 and track.height > 576:
                resolution = "HD"
            elif track.height <= 576:
                resolution = "SD"

            if track.hdr10:
                range_ = "HDR10"
            elif track.dv:
                range_ = "DOLBY_VISION"
            elif track.hlg:
                range_ = "HLG"
            else:
                range_ = "SDR"

            if "mpl" in track.codec:
                profile = "MPL"
            elif "hpl" in track.codec:
                profile = "HPL"
            else:
                profile = ""

            return kind, title_name, "VIDEO", resolution, range_, profile
        elif isinstance(track, AudioTrack):
            return kind, title_name, "AUDIO", "", "", ""
        else:
            return kind, title_name, "", "", "", ""
