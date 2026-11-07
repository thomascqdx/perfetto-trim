"""perfetto-trim - Perfetto Trim: trim/split large perfetto traces with bounded memory."""

__version__ = "1.3.0"


class Cancelled(Exception):
    """Operation cancelled via a threading.Event flag."""
