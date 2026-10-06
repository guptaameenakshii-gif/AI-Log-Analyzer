import re
from datetime import datetime, timezone


# Timestamp formats commonly found in security/application logs.
#
# The parser deliberately supports only formats that can be
# deterministically interpreted. It never invents missing dates
# or times.

def classify_timeline_severity(log_line: str) -> str:
    """
    Assign conservative severity to a timeline event based only on
    observable wording in the original log line.

    This is a display severity for the deterministic timeline.
    It is not a security verdict.
    """

    text = log_line.lower()

    high_indicators = (
        "malware detected",
        "ransomware",
        "account takeover",
        "intrusion detected",
        "critical intrusion",
        "unauthorized access confirmed",
    )

    medium_indicators = (
        "failed login",
        "authentication failure",
        "login denied",
        "permission denied",
        "account temporarily locked",
        "invalid token",
        "authentication service timeout",
        "password rejected",
        "access denied",
    )

    if any(
        indicator in text
        for indicator in high_indicators
    ):
        return "HIGH"

    if any(
        indicator in text
        for indicator in medium_indicators
    ):
        return "MEDIUM"

    return "INFO"


TIMESTAMP_PATTERNS = [
    # ISO 8601 / standard datetime:
    # 2026-09-25 11:00:00
    # 2026-09-25T11:00:00
    # 2026-09-25 11:00:00.123
    # 2026-09-25T11:00:00Z
    (
        re.compile(
            r"(?<!\d)"
            r"(\d{4}-\d{2}-\d{2}"
            r"[T ]"
            r"\d{2}:\d{2}"
            r"(?::\d{2})?"
            r"(?:[.,]\d+)?"
            r"(?:Z|[+-]\d{2}:?\d{2})?)"
            r"(?!\d)"
        ),
        [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
             "%Y-%m-%d %H:%M",
            "%Y-%m-%dT%H:%M",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%d %H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S.%f%z",
        ],
    ),

    # Slash-separated datetime:
    # 2026/09/25 08:12:36
    # 09/25/2026 08:12:36
    # 25/09/2026 08:12:36
    (
        re.compile(
            r"(?<!\d)"
            r"(\d{2,4}/\d{1,2}/\d{1,4}"
            r"[ T]"
            r"\d{2}:\d{2}"
            r"(?::\d{2})?)"
            r"(?!\d)"
        ),
        [
            "%Y/%m/%d %H:%M:%S",
            "%Y/%m/%dT%H:%M:%S",
            "%Y/%m/%d %H:%M",
            "%Y/%m/%dT%H:%M",
            "%m/%d/%Y %H:%M:%S",
            "%d/%m/%Y %H:%M:%S",
            "%m/%d/%Y %H:%M",
            "%d/%m/%Y %H:%M",
        ],
    ),

    # Dash-separated datetime:
    # 09-25-2026 08:12:36
    # 25-09-2026 08:12:36
    (
        re.compile(
            r"(?<!\d)"
            r"(\d{2,4}-\d{1,2}-\d{1,4}"
            r"[ T]"
            r"\d{2}:\d{2}"
            r"(?::\d{2})?)"
            r"(?!\d)"
        ),
        [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M",
            "%Y-%m-%dT%H:%M",
            "%m-%d-%Y %H:%M:%S",
            "%d-%m-%Y %H:%M:%S",
            "%m-%d-%Y %H:%M",
            "%d-%m-%Y %H:%M",
        ],
    ),

    # Syslog-style timestamps:
    # Sep 25 15:11:13
    # Sep  5 15:11:13
    (
        re.compile(
            r"\b"
            r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
            r"\s+"
            r"\d{1,2}"
            r"\s+"
            r"\d{2}:\d{2}:\d{2}"
            r"\b",
            re.IGNORECASE,
        ),
        [
            "%b %d %H:%M:%S",
        ],
    ),

    # Time-only format:
    # 15:11:13
    #
    # This is intentionally treated as a valid timestamp for ordering
    # within the supplied input, but it is not assigned a date.
    (
        re.compile(
            r"(?<!\d)"
            r"(\d{2}:\d{2}:\d{2})"
            r"(?!\d)"
        ),
        [
            "%H:%M:%S",
        ],
    ),
]


def extract_timestamp(line: str):
    """
    Extract and normalize a timestamp from one log line.

    Returns:
        {
            "original": original timestamp,
            "normalized": ISO-style timestamp,
            "sort_key": datetime
        }

    or None when no reliable timestamp is found.

    Important:
    - The original timestamp is preserved.
    - No missing date is invented.
    - Time-only and syslog timestamps use a synthetic anchor date
      only for deterministic ordering within the supplied input.
      The displayed timestamp remains exactly as observed.
    """

    for pattern, formats in TIMESTAMP_PATTERNS:
        match = pattern.search(line)

        if not match:
            continue

        original = match.group(1)

        for fmt in formats:
            try:
                parsed = datetime.strptime(
                    original,
                    fmt,
                )
                if parsed.tzinfo is not None:
                    sort_key = parsed.astimezone(
                        timezone.utc
                    ).replace(
                        tzinfo=None
                    )
                else:
                    sort_key = parsed

                # Syslog and time-only records have no year/date.
                # datetime.strptime uses a default date for these,
                # which is useful only as an internal sort key.
                return {
                    "original": original,
                    "normalized": (
                        parsed.isoformat(
                            timespec="seconds"
                        )
                    ),
                    "sort_key": sort_key,
                }

            except ValueError:
                continue

    return None


def extract_timeline_candidates(log_text: str):
    """
    Extract timeline candidates from every non-empty input line.

    Every original log line is preserved.

    Timestamped lines receive a parsed timestamp.
    Untimestamped lines receive:

        timestamp = "Unknown"

    This makes the timeline evidence-complete instead of silently
    dropping records that do not contain timestamps.
    """

    candidates = []

    for line_number, line in enumerate(
        log_text.splitlines(),
        start=1,
    ):
        original_line = line.strip()

        if not original_line:
            continue

        timestamp = extract_timestamp(
            original_line
        )

        if timestamp:
            candidates.append(
                {
                    "line_number": line_number,
                    "timestamp": timestamp["original"],
                    "normalized_timestamp": timestamp[
                        "normalized"
                    ],
                    "sort_key": timestamp["sort_key"],
                    "original_log": original_line,
                }
            )
        else:
            candidates.append(
                {
                    "line_number": line_number,
                    "timestamp": "Unknown",
                    "normalized_timestamp": None,
                    "sort_key": None,
                    "original_log": original_line,
                }
            )

    return candidates


def sort_timeline_candidates(candidates):
    """
    Sort timeline candidates chronologically.

    Rules:
    1. Valid timestamps first.
    2. Chronological order for comparable timestamps.
    3. Unknown timestamps last.
    4. Original input order is preserved for equal/unknown events.
    """

    indexed = list(
        enumerate(candidates)
    )

    indexed.sort(
        key=lambda item: (
            item[1]["sort_key"] is None,
            (
                item[1]["sort_key"]
                if item[1]["sort_key"] is not None
                else datetime.max
            ),
            item[0],
        )
    )

    return [
        candidate
        for _, candidate in indexed
    ]
