#!/usr/bin/env python3
"""Map the product's calendar VERSION to Apple's numeric bundle versions."""

from datetime import date
from pathlib import Path
import re
import sys


VERSION_PATTERN = re.compile(
    r"v([0-9]{4})\.([0-9]{1,2})\.([0-9]{1,2})(?:\.([0-9]{1,2})[._]([0-9]{2}))?"
)


def bundle_versions(contents: str) -> tuple[str, str, str]:
    """Return raw, marketing, build versions; accept one optional line ending.

    Build patch is the zero-based minute of the month. This retains chronological
    order and the historical HH_MM / HH.MM suffix without exceeding three parts.
    A date-only version means midnight. Redistributing a changed build requires
    a later VERSION (including its time suffix for another build that day).
    """
    raw = contents.removesuffix("\n").removesuffix("\r")
    match = VERSION_PATTERN.fullmatch(raw)
    if match is None:
        raise ValueError("VERSION must be vYYYY.M.D with optional .HH_MM or .HH.MM")
    year, month, day = map(int, match.group(1, 2, 3))
    date(year, month, day)  # Reject impossible dates, including year zero.
    hour, minute = int(match[4] or 0), int(match[5] or 0)
    if hour > 23 or minute > 59:
        raise ValueError("VERSION time must be between 00:00 and 23:59")
    patch = (day - 1) * 1440 + hour * 60 + minute
    return raw, f"{year}.{month}.{day}", f"{year}.{month}.{patch}"


if __name__ == "__main__":
    try:
        values = bundle_versions(Path(sys.argv[1]).read_text(encoding="ascii"))
    except (IndexError, OSError, UnicodeError, ValueError) as error:
        sys.exit(f"ERROR: Invalid VERSION: {error}")
    print("\t".join(values))
