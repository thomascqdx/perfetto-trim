"""pftrim - Perfetto Trim: trim/split large perfetto traces with bounded memory."""

__version__ = "1.1.0"


class Cancelled(Exception):
    """Operation cancelled via a threading.Event flag."""
