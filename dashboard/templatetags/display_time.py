"""One timestamp display format for HTML pages and their live updates."""

from datetime import datetime

from django import template
from django.utils.formats import date_format
from django.utils.timezone import get_default_timezone


register = template.Library()


@register.filter
def readable_timestamp(value, fallback="Not available"):
    """Display an aware datetime or stored ISO timestamp in the dashboard zone.

    For example: 2 Nov 2026, 1:08:02 AM WAT. Fractions of a second are useful
    in storage but unnecessary in the label. Missing times are never guessed.
    """
    if not value:
        return fallback
    try:
        if isinstance(value, str):
            value = datetime.fromisoformat(value.removesuffix("Z") + "+00:00" if value.endswith("Z") else value)
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            return fallback
        display_time = value.astimezone(get_default_timezone())
    except (ValueError, OverflowError):
        return fallback
    return date_format(display_time, "j M Y, g:i:s A", use_l10n=False) + f" {display_time.tzname()}"
