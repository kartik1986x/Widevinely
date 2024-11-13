from __future__ import annotations

import hashlib
import re
import validators

from pathlib import Path
from typing import Optional, Union
from widevinely.utils import logger

log = logger.getLogger("credential")


class Credential:
    """Username (or Email) and Password Credential."""

    def __init__(self, username: str, password: str, extra: Optional[str] = None):
        self.username = username
        self.password = password
        self.extra = extra
        self.sha1 = hashlib.sha1(self.dumps().encode()).hexdigest()

    def __bool__(self) -> bool:
        return bool(self.username) and bool(self.password)

    def __str__(self) -> str:
        return self.dumps()

    def __repr__(self) -> str:
        return "{name}({items})".format(
            name=self.__class__.__name__,
            items=", ".join([f"{k}={repr(v)}" for k, v in self.__dict__.items()]),
        )

    def dumps(self) -> str:
        """Return credential data as a string."""
        return f"{self.username}:{self.password}" + (
            f":{self.extra}" if self.extra else ""
        )

    def dump(self, path) -> int:
        """Write credential data to a file."""
        if isinstance(path, str):
            path = Path(path)
        return path.write_text(self.dumps(), encoding="utf8")

    @classmethod
    def loads(cls, text) -> Credential:
        """
        Load credential from a text string.

        Format: {username}:{password}
        Rules:
            Only one Credential must be in this text contents.
            All whitespace before and after all text will be removed.
            Any whitespace between text will be kept and used.
            The credential can be spanned across one or multiple lines as long as it
                abides with all the above rules and the format.

        Example that follows the format and rules:
            `\tJohnd\noe@gm\n\rail.com\n:Pass1\n23\n\r  \t  \t`
            >>>Credential(username='Johndoe@gmail.com', password='Pass123')
        """
        text = "".join([x.strip() for x in text.splitlines(keepends=False)]).strip()
        credential = re.fullmatch(r"^([^:]+?):([^:]+?)(?::(.+))?$", text)
        if credential:
            return cls(*credential.groups())
        ValueError
        log.exit(
            "No credentials found in text string. Expecting the format `username:password`"
        )

    @classmethod
    def load(cls, uri: Union[str, Path], session=None) -> Credential:
        """
        Load Credential from a remote URL string or a local file Path object.
        Use Credential.loads() for loading from text content and seeing the rules and
        format expected to be found in the URIs contents.

        Parameters:
            uri: Remote URL string or a local file Path object.
            session: Python-requests session to use for Remote URL strings. This can be
                used to set custom Headers, Proxies, etc.
        """
        if isinstance(uri, Path):
            # local file
            return cls.loads(uri.read_text("utf8"))
        if validators.url(uri):
            # remote file
            return cls.loads((session).get(uri).text)
        ValueError
        log.exit(
            "Unrecognized Credentials URI. It must be a local file or a remote URL."
        )
