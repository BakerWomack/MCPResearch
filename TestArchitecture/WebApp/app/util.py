"""Small shared helpers for the webapp."""

from datetime import datetime, timezone


def wall_clock_ms() -> str:
    """UTC time as HH:MM:SS.mmm for log correlation."""
    return datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3]
