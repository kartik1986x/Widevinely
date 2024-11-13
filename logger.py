import logging
from io import IOBase
import coloredlogs

from pywidevinely.utils import console

LOG_FORMAT = "{asctime} {name} : {message}"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
LOG_STYLE = "{"
LOG_FORMATTER = logging.Formatter(LOG_FORMAT, LOG_DATE_FORMAT, LOG_STYLE)


class Logger(logging.Logger):
    def __init__(self, name="pywidevinely", level=logging.NOTSET, color=True):
        """Initialize the logger with a name and an optional level."""
        super().__init__(name, level)
        if self.name == "logger":
            self.add_stream_handler()
        if color:
            self.install_color()

    def success_(self, msg, style="green", debug=True):
        """
        Printing the message and return.
        When it's an internal message it will log and return.
        """
        if debug:
            self.debug(msg)
        else:
            console.print(msg, style=style)
        return

    def info_(self, msg, style=None, debug=False):
        """
        Printing the message and return.
        When it's an internal message it will log and return.
        """
        if debug:
            self.info(msg)
        else:
            console.print(msg, style=style)
        return

    def error_(self, msg, style="red", debug=True):
        """
        Printing the error and return.
        When it's an internal error it will log and return.
        """
        if debug:
            self.error(msg)
        else:
            console.print(msg, style=style)
        return

    def warning_(self, msg, debug=False):
        """
        Printing a warning and return.
        When it's an internal warning it will warn and return.
        """
        if debug:
            self.warning(msg)
        else:
            console.print(msg, style="warning")
        return

    def exit(self, msg, debug=False):
        """
        Printing the error and exit.
        When it's an internal error it will log and exit.
        """
        if debug:
            self.critical(msg)
        else:
            console.print(msg, style="error")
        exit()

    def add_stream_handler(self, stream=None):
        """Add a stream handler to log. Stream defaults to stdout."""
        sh = logging.StreamHandler(stream)
        sh.setFormatter(LOG_FORMATTER)
        self.addHandler(sh)

    def add_file_handler(self, fp):
        """Convenience alias func for add_stream_handler, deals with type of fp object input."""
        if not isinstance(fp, IOBase):
            fp = open(fp, "w", encoding="utf-8")
        self.add_stream_handler(fp)

    def install_color(self):
        """Use coloredlogs to set up colors on the log output."""
        if self.level == logging.DEBUG:
            coloredlogs.install(
                level=self.level,
                fmt=LOG_FORMAT,
                datefmt=LOG_DATE_FORMAT,
                style=LOG_STYLE,
            )
        coloredlogs.install(
            level=self.level,
            logger=self,
            fmt=LOG_FORMAT,
            datefmt=LOG_DATE_FORMAT,
            style=LOG_STYLE,
        )


# Cache already used loggers to make sure their level is preserved
_loggers = {}


# noinspection PyPep8Naming
def getLogger(name=None, api=False, level=logging.NOTSET):
    name = (
        f"pywidevinely.{name}"
        if name and not api
        else name
        if name and api
        else "pywidevinely"
    )
    _log = _loggers.get(name, Logger(name))
    _log.setLevel(level)
    return _log
