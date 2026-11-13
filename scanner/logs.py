"""Progress logging for InfraScan: timestamped lines on stderr, plus stage timing.

Progress goes to stderr so stdout stays the report itself (`--format json` or
`html` without `--out` prints the report there). CI logs show both streams.
"""
import logging
import sys
import time
from contextlib import contextmanager
from typing import Iterator, Optional

# Only our own packages get the handler. Third-party libraries keep their own
# logging (Checkov, imported in-process, installs a root handler of its own),
# so our records don't propagate to the root logger and get printed twice.
_OWN_LOGGERS = ("cli", "scanner", "reporter", "ci_adapters")


class _Formatter(logging.Formatter):
    """`[2026-01-31 12:00:00] message`; warnings and errors also name their level."""

    def __init__(self) -> None:
        super().__init__(datefmt="%Y-%m-%d %H:%M:%S")

    def format(self, record: logging.LogRecord) -> str:
        line = f"[{self.formatTime(record, self.datefmt)}] "
        if record.levelno >= logging.WARNING:
            line += f"{record.levelname}: "
        line += record.getMessage()
        if record.exc_info:
            line += "\n" + self.formatException(record.exc_info)
        return line


def setup_logging(level: int = logging.INFO) -> None:
    """Send our log records to stderr with timestamps. Safe to call more than once."""
    for name in _OWN_LOGGERS:
        logger = logging.getLogger(name)
        logger.setLevel(level)
        logger.propagate = False
        if not any(getattr(h, "_infrascan", False) for h in logger.handlers):
            handler = logging.StreamHandler(sys.stderr)
            handler.setFormatter(_Formatter())
            handler._infrascan = True  # type: ignore[attr-defined]
            logger.addHandler(handler)


def format_duration(seconds: float) -> str:
    """12.3s below a minute, 4m 05s above."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, secs = divmod(int(round(seconds)), 60)
    return f"{minutes}m {secs:02d}s"


@contextmanager
def timed(logger: logging.Logger, stage: str, start_message: Optional[str] = None) -> Iterator[None]:
    """Log the start and the duration of a stage, so slow stages stand out in CI logs."""
    logger.info(start_message or f"{stage}...")
    start = time.monotonic()
    try:
        yield
    except BaseException:
        logger.info(f"{stage} stopped after {format_duration(time.monotonic() - start)}")
        raise
    logger.info(f"{stage} finished in {format_duration(time.monotonic() - start)}")
