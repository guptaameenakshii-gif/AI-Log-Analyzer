import os
import re
from datetime import datetime
import ipaddress
from copy import deepcopy

from langfuse import propagate_attributes

from .llm import analyze_logs_with_ai
from .observability import get_langfuse_client, mask_sensitive_data
from .schemas import TimelineEvent
from .timeline import (
    classify_timeline_severity,
    extract_timeline_candidates,
    find_malformed_timestamps,
    sort_timeline_candidates,
)


MAX_LOG_CHARACTERS = 240_000
MIN_MEANINGFUL_CHARACTERS = 10

def _redact_report_evidence(text: str) -> str:
    """Redact usernames in report evidence regardless of observability settings."""
    return re.sub(
        r"(\buser\s*[=:]\s*['\"]?)[a-zA-Z0-9_.@-]+",
        r"\1[REDACTED]",
        str(text or ""),
        flags=re.IGNORECASE,
    )

def _trace_step(
    name,
    operation,
    *args,
    trace_input=None,
    trace_output=None,
    **kwargs,
):
    """Run one operation as a child span with optional compact payloads."""

    try:
        observation = get_langfuse_client().start_as_current_observation(
            name=name,
            as_type="span",
        )
    except Exception:
        return operation(*args, **kwargs)

    with observation as span:
        if trace_input is not None:
            try:
                span.update(
                input=mask_sensitive_data(data=trace_input)
            )
            except Exception:
                pass

        try:
            result = operation(*args, **kwargs)
        except Exception as exc:
            try:
                span.update(
                    level="ERROR",
                    status_message=str(
                        mask_sensitive_data(data=str(exc))
                    )[:500],
                )
            except Exception:
                pass
            raise

        if trace_output is not None:
            try:
                span.update(
                output=mask_sensitive_data(data=trace_output(result))
                )
            except Exception:
                pass

    return result


TRACE_ITEM_LIMIT = 100


def _analysis_trace_snapshot(analysis):
    """Return the correctness-relevant analysis fields for trace review."""

    analysis = _analysis_to_dict(analysis)
    findings = analysis.get("findings", []) or []
    timeline = analysis.get("timeline", []) or []

    return {
        "executive_summary": analysis.get("executive_summary"),
        "overall_risk": analysis.get("overall_risk"),
        "confidence": analysis.get("confidence"),
        "findings": [
            {
                key: finding.get(key)
                for key in (
                    "title",
                    "severity",
                    "confidence",
                    "description",
                    "evidence",
                    "attack_pattern",
                )
                if key in finding
            }
            for finding in findings[:TRACE_ITEM_LIMIT]
            if isinstance(finding, dict)
        ],
        "timeline": [
            event
            if isinstance(event, dict)
            else _analysis_to_dict(event)
            for event in timeline[:TRACE_ITEM_LIMIT]
        ],
        "data_quality_notes": analysis.get("data_quality_notes", []),
        "investigation_priority": analysis.get("investigation_priority", []),
        "finding_count": len(findings),
        "timeline_count": len(timeline),
    }


def _analysis_trace_changes(before, after):
    """Describe fields changed by deterministic evidence-safety checks."""

    before = _analysis_to_dict(before)
    after = _analysis_to_dict(after)
    changes = {}

    for key in ("executive_summary", "overall_risk", "confidence"):
        if before.get(key) != after.get(key):
            changes[key] = {
                "before": before.get(key),
                "after": after.get(key),
            }

    before_findings = before.get("findings", []) or []
    after_findings = after.get("findings", []) or []
    finding_changes = []
    for index, (old, new) in enumerate(zip(before_findings, after_findings)):
        if not isinstance(old, dict) or not isinstance(new, dict):
            continue
        changed_fields = {
            field: {"before": old.get(field), "after": new.get(field)}
            for field in ("title", "description", "evidence", "severity", "confidence")
            if old.get(field) != new.get(field)
        }
        if changed_fields:
            finding_changes.append({"index": index, **changed_fields})
    if finding_changes:
        changes["findings"] = finding_changes

    old_notes = before.get("data_quality_notes", []) or []
    new_notes = after.get("data_quality_notes", []) or []
    added_notes = [note for note in new_notes if note not in old_notes]
    if added_notes:
        changes["data_quality_notes_added"] = added_notes

    return changes


def _data_quality_issue_records(notes):
    records = []
    for note in notes or []:
        description = str(note)
        lowered = description.lower()
        if "malformed timestamp" in lowered or "timestamp" in lowered:
            issue_type = "timestamp_quality"
        elif "contradictory" in lowered:
            issue_type = "contradictory_evidence"
        elif "compromise" in lowered or "claim" in lowered:
            issue_type = "unverified_claim"
        elif "private ip" in lowered or "rfc1918" in lowered:
            issue_type = "ip_classification"
        else:
            issue_type = "data_quality"
        records.append({"type": issue_type, "description": description})
    return records


def _trace_log_excerpt(log_text, max_lines=TRACE_ITEM_LIMIT):
    return {
        "lines": log_text.splitlines()[:max_lines],
        "total_lines": len(log_text.splitlines()),
    }


def _timeline_trace_rows(timeline):
    timeline = timeline or []
    return {
        "events": [
            _analysis_to_dict(event)
            for event in timeline[:TRACE_ITEM_LIMIT]
        ],
        "total_events": len(timeline),
    }


VALID_SEVERITIES = {
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "INFO",
}


SEVERITY_ALIASES = {
    "WARN": "MEDIUM",
    "WARNING": "MEDIUM",
    "ERROR": "HIGH",
    "ERR": "HIGH",
    "DEBUG": "INFO",
    "NOTICE": "INFO",
}


# ---------------------------------------------------------------------------
# Input preparation
# ---------------------------------------------------------------------------

def _prepare_logs(log_text: str) -> str:
    """
    Validate and normalize raw input.

    This function does not perform security interpretation.
    """

    if not log_text:
        return ""

    log_text = str(log_text).strip()

    if not log_text:
        return ""

    if len(log_text) > MAX_LOG_CHARACTERS:
        raise ValueError(
            f"Log input is too large. "
            f"Maximum supported size is "
            f"{MAX_LOG_CHARACTERS:,} characters."
        )

    return log_text


# ---------------------------------------------------------------------------
# Severity normalization
# ---------------------------------------------------------------------------

def _normalize_severity(
    severity,
    fallback: str = "INFO",
) -> str:
    """
    Normalize severity into the values accepted by SecurityAnalysis.
    """

    if severity is None:
        return fallback

    value = str(severity).strip().upper()

    if value in VALID_SEVERITIES:
        return value

    return SEVERITY_ALIASES.get(
        value,
        fallback,
    )


# ---------------------------------------------------------------------------
# Timestamp validation
# ---------------------------------------------------------------------------

def _is_valid_timestamp(timestamp: str) -> bool:
    """
    Determine whether a timestamp is valid.

    This function never repairs malformed timestamps.
    """

    if not timestamp:
        return False

    value = str(timestamp).strip()

    formats = (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S.%f%z",
    )

    for fmt in formats:
        try:
            datetime.strptime(
                value,
                fmt,
            )
            return True
        except ValueError:
            continue

    return False


def _has_malformed_timestamp(log_text: str) -> bool:
    """
    Detect malformed full datetime values.

    Example:

        2026-99-44 77:88:99

    is detected but never corrected.
    """

    pattern = re.compile(
        r"(?<!\d)"
        r"\d{4}-\d{2}-\d{2}"
        r"[T ]"
        r"\d{2}:\d{2}:\d{2}"
        r"(?!\d)"
    )

    for match in pattern.finditer(log_text):
        timestamp = match.group(0)

        if not _is_valid_timestamp(timestamp):
            return True

    return False


# ---------------------------------------------------------------------------
# Deterministic timeline
# ---------------------------------------------------------------------------

def _is_private_ip(value: str) -> bool:
    """
    Return True when the supplied IP address belongs to a private
    address range.

    Invalid/non-IP values return False rather than being treated
    as private.
    """

    if not isinstance(value, str):
        return False

    value = value.strip()

    if not value:
        return False

    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False

    if isinstance(address, ipaddress.IPv4Address):
        return any(
            address in network
            for network in (
                ipaddress.ip_network("10.0.0.0/8"),
                ipaddress.ip_network("172.16.0.0/12"),
                ipaddress.ip_network("192.168.0.0/16"),
            )
        )

    return address.is_private


def _correct_private_ip_labels(analysis, log_text: str):
    """Prevent direct external-IP labels for RFC1918 addresses in the input."""

    addresses = {
        match.group(0)
        for match in re.finditer(
            r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])",
            log_text,
        )
        if _is_private_ip(match.group(0))
    }

    if not addresses:
        return analysis

    changed = False

    def normalize_text(value):
        nonlocal changed

        if not isinstance(value, str):
            return value

        for address in addresses:
            escaped = re.escape(address)
            external_before = re.compile(
                rf"\bexternal(?:\s+(?:source|client|host|IP|address)){{0,2}}"
                rf"\s*[:=]?\s*{escaped}\b",
                re.IGNORECASE,
            )
            external_after = re.compile(
                rf"\b{escaped}\b\s+(?:is|was|appears to be)\s+"
                rf"(?:an?\s+)?external\b",
                re.IGNORECASE,
            )
            value, first_count = external_before.subn(
                f"private/internal IP {address}",
                value,
            )
            value, second_count = external_after.subn(
                f"{address} is private/internal",
                value,
            )
            changed = changed or bool(first_count or second_count)

        return value

    summary = _analysis_field(
        analysis,
        "executive_summary",
        "",
    )
    _set_analysis_field(
        analysis,
        "executive_summary",
        normalize_text(summary),
    )

    findings = _analysis_field(analysis, "findings", []) or []
    for finding in findings:
        for field_name in (
            "title",
            "description",
            "attack_pattern",
            "recommended_actions",
        ):
            value = _analysis_field(finding, field_name, None)
            if isinstance(value, list):
                value = [normalize_text(item) for item in value]
            else:
                value = normalize_text(value)
            if value is not None:
                _set_analysis_field(finding, field_name, value)

    for event in _analysis_field(analysis, "timeline", []) or []:
        event_description = _analysis_field(event, "event", None)
        if event_description is not None:
            _set_analysis_field(
                event,
                "event",
                normalize_text(event_description),
            )

    priorities = _analysis_field(
        analysis,
        "investigation_priority",
        None,
    )
    if isinstance(priorities, list):
        _set_analysis_field(
            analysis,
            "investigation_priority",
            [normalize_text(priority) for priority in priorities],
        )

    if changed:
        _append_data_quality_note(
            analysis,
            "RFC1918 private IP addresses in the input were not classified as external.",
        )

    return analysis



def _describe_timeline_event(log_line: str) -> str:
    """
    Produce a concise, deterministic description of a recognizable
    log event without asserting that an attack is confirmed.

    Descriptions are based on observable wording only.
    Unrecognized entries receive a neutral fallback.
    """
    text = log_line.casefold()
    if re.match(r"^\s*analyst note\s*:", log_line, re.IGNORECASE):
        return "Analyst assertion; not independently verified."

    patterns = (
        (
            (
                "failed login",
                "login failed",
                "authentication failed",
                "auth failure",
                "login denied",
                "password rejected",
                "invalid credentials",
                "authentication failure",
                "login failure",
                "authentication denied",
            ),
            "Log records an authentication failure.",
        ),
        (
            (
                "successful login",
                "login successful",
                "authentication succeeded",
                "authentication successful",
                "authentication success",
                "login success",
                "authenticated successfully",
                "login accepted",
            ),
            "Log records a successful authentication.",
        ),
        (
            (
                "account temporarily locked",
                "account locked",
                "account lockout",
                "account locked out",
            ),
            "Log records an account-lockout event.",
        ),
        (
            (
                "permission denied",
                "access denied",
                "forbidden",
            ),
            "Log records an access-denied event.",
        ),
        (
            (
                "invalid token",
                "expired token",
            ),
            "Log records an invalid or expired token.",
        ),
        (
            (
                "ransomware",
                "malware",
                "trojan",
                "virus",
            ),
            "Log contains a malware-related indicator.",
        ),
        (
            (
                "unauthorized access",
                "intrusion",
            ),
            "Log contains wording indicating unauthorized access.",
        ),
    )

    for indicators, description in patterns:
        if any(indicator in text for indicator in indicators):
            return description

    return "Observed log entry; no recognized event pattern."


def _correlate_authentication_events(timeline, original_log_text=None):
    """
    Group repeated authentication failures by user internally.
    Return pseudonymous account labels, never original usernames.
    """
    import re
    from collections import defaultdict

    failures_by_user = defaultdict(list)

    for event in timeline:
        evidence = str(getattr(event, "evidence", "") or "")

        if not re.search(
            r"authentication\s+failed|failed\s+login|"
            r"login\s+failed|authentication\s+failure",
            evidence,
            re.IGNORECASE,
        ):
            continue

        line_number = getattr(event, "line_number", None)
        if line_number is None or original_log_text is None:
            continue

        lines = original_log_text.splitlines()
        if line_number < 1 or line_number > len(lines):
            continue

        original_line = lines[line_number - 1]
        match = re.search(
            r"\buser\s*[=:]\s*['\"]?([a-zA-Z0-9_.@-]+)",
            original_line,
            re.IGNORECASE,
        )
        if not match:
            continue

        user = match.group(1)
        failures_by_user[user].append(event)

    correlations = []
    for events in failures_by_user.values():
        if len(events) < 2:
            continue

        correlations.append({
            "user": f"account_{len(correlations) + 1}",
            "event_count": len(events),
            "line_numbers": sorted(
                event.line_number
                for event in events
                if event.line_number is not None
            ),
        })

    return correlations

def _build_deterministic_timeline(
    log_text: str,
) -> list[TimelineEvent]:
    """
    Build a timeline from the original log input.

    Python remains authoritative for timestamp extraction, ordering,
    severity classification, evidence preservation, and line numbers.
    Event descriptions use conservative deterministic text patterns.

    This timeline is not itself a security verdict.
    """
    candidates = extract_timeline_candidates(log_text)
    candidates = sort_timeline_candidates(candidates)

    timeline = []

    for candidate in candidates:
        original_log = candidate["original_log"]
        timestamp = candidate["timestamp"]

        severity = classify_timeline_severity(original_log)
        event_description = _describe_timeline_event(original_log)

        timeline.append(
            TimelineEvent(
                timestamp=timestamp,
                event=event_description,
                severity=severity,
                evidence=(
                    f"Line {candidate['line_number']}: "
                    f"{_redact_report_evidence(original_log)}"
                ),
                line_number=candidate["line_number"],
            )
        )

    return timeline

# ---------------------------------------------------------------------------
# AI timeline helpers
# ---------------------------------------------------------------------------

def _get_ai_timeline_value(
    ai_event,
    field_name: str,
    default=None,
):
    """
    Read a field from either a dictionary or Pydantic model.
    """

    if ai_event is None:
        return default

    if isinstance(ai_event, dict):
        return ai_event.get(
            field_name,
            default,
        )

    return getattr(
        ai_event,
        field_name,
        default,
    )


def _merge_ai_timeline_with_deterministic_timeline(
    ai_timeline,
    deterministic_timeline,
):
    """
    Merge AI interpretation into the deterministic timeline.

    Python remains authoritative for timestamps, ordering,
    original evidence, and source line numbers.
    AI may provide event descriptions and severity.
    Events are matched only when timestamps are unambiguous.
    """
    if not deterministic_timeline:
        return ai_timeline or []

    ai_timeline = ai_timeline or []
    ai_by_timestamp = {}
    deterministic_counts = {}

    for event in deterministic_timeline:
        timestamp = _get_ai_timeline_value(
            event, "timestamp", "Unknown"
        )
        deterministic_counts[timestamp] = (
            deterministic_counts.get(timestamp, 0) + 1
        )

    for ai_event in ai_timeline:
        timestamp = _get_ai_timeline_value(
            ai_event, "timestamp", None
        )
        if timestamp is None:
            continue

        timestamp = str(timestamp).strip()
        if timestamp:
            ai_by_timestamp.setdefault(timestamp, []).append(ai_event)

    merged = []

    for event in deterministic_timeline:
        timestamp = _get_ai_timeline_value(
            event, "timestamp", "Unknown"
        )

        matching_events = ai_by_timestamp.get(timestamp, [])
        ai_event = (
            matching_events[0]
            if timestamp != "Unknown"
            and deterministic_counts.get(timestamp) == 1
            and len(matching_events) == 1
            else None
        )

        ai_description = _get_ai_timeline_value(
            ai_event, "event", ""
        )
        ai_severity = _get_ai_timeline_value(
            ai_event, "severity", None
        )

        merged.append(
            TimelineEvent(
                timestamp=timestamp,
                event=(
                    ai_description
                    or _get_ai_timeline_value(event, "event", "")
                ),
                severity=_normalize_severity(
                    ai_severity,
                    fallback=_get_ai_timeline_value(
                        event, "severity", "INFO"
                    ),
                ),
                evidence=_get_ai_timeline_value(
                    event, "evidence", ""
                ),
                line_number=_get_ai_timeline_value(
                    event, "line_number", None
                ),
            )
        )

    return merged


# ---------------------------------------------------------------------------
# Generic analysis helpers
# ---------------------------------------------------------------------------

def _analysis_to_dict(analysis):
    """
    Convert Pydantic analysis to a plain dictionary.
    """

    if analysis is None:
        return {}

    if isinstance(analysis, dict):
        return dict(analysis)

    if hasattr(
        analysis,
        "model_dump",
    ):
        return analysis.model_dump()

    return dict(analysis)


def _analysis_field(
    analysis,
    field_name,
    default=None,
):
    """
    Safely read a top-level analysis field.
    """

    if isinstance(analysis, dict):
        return analysis.get(
            field_name,
            default,
        )

    return getattr(
        analysis,
        field_name,
        default,
    )


def _set_analysis_field(
    analysis,
    field_name,
    value,
):
    """
    Safely update a top-level analysis field.
    """

    if isinstance(analysis, dict):
        analysis[field_name] = value
    else:
        setattr(
            analysis,
            field_name,
            value,
        )


def _text_contains_any(
    text,
    phrases,
):
    """
    Case-insensitive phrase matching.
    """

    text = str(
        text or ""
    ).lower()

    return any(
        phrase.lower() in text
        for phrase in phrases
    )

def _analysis_text(analysis):
    """
    Collect user-visible analysis text so deterministic safety checks
    can inspect the entire AI response.
    """
    parts = []

    summary = _analysis_field(
        analysis,
        "executive_summary",
        "",
    )

    if summary:
        parts.append(str(summary))

    for finding in (
        _analysis_field(
            analysis,
            "findings",
            [],
        )
        or []
    ):
        for field in (
            "title",
            "description",
            "evidence",
            "attack_pattern",
        ):
            value = _analysis_field(
                finding,
                field,
                "",
            )

            if isinstance(value, list):
                parts.extend(
                    str(item)
                    for item in value
                )
            elif value:
                parts.append(str(value))

    return " ".join(parts)



def _has_direct_compromise_evidence(log_text):
    """
    Conservatively identify compromise indicators in telemetry-style
    log entries, not in free-form analyst notes or narrative claims.
    """
    import re

    text = str(log_text or "")

    direct_indicators = (
        "unauthorized access confirmed",
        "account takeover confirmed",
        "compromise confirmed",
        "breach confirmed",
        "attacker successfully accessed",
        "malware execution confirmed",
    )

    timestamp_pattern = re.compile(
        r"^\s*(?:\d{4}-\d{2}-\d{2}[T ]|\[?\w{3}\s+\d{1,2}\s+\d{2}:)"
    )

    structured_markers = (
        "event=",
        "event_type=",
        "action=",
        "alert=",
        "signature=",
        "detection=",
        "rule=",
    )

    for line in text.splitlines():
        normalized = line.lower().strip()

        if not any(
            indicator in normalized
            for indicator in direct_indicators
        ):
            continue

        is_timestamped = bool(
            timestamp_pattern.search(line)
        )
        is_structured = any(
            marker in normalized
            for marker in structured_markers
        )

        if is_timestamped or is_structured:
            return True

    return False


def _contains_unsupported_compromise_confirmation(text):
    """
    Detect language that presents compromise as established fact
    without sufficient supporting evidence.
    """
    text = str(text or "").lower()

    unsafe_patterns = (
        "confirmed compromise",
        "confirmed breach",
        "compromise occurred",
        "breach occurred",
        "the system was compromised",
        "the account was compromised",
        "the server was compromised",
        "the account has been compromised",
        "the system has been compromised",
        "the server has been compromised",
        "attacker successfully accessed",
        "attacker gained access",
        "unauthorized access was confirmed",
        "unauthorized access confirmed",
        "this confirms compromise",
        "this confirms a compromise",
        "this confirms the breach",
        "this indicates compromise",
        "this indicates a compromise",
    )

    return any(
        pattern in text
        for pattern in unsafe_patterns
    )

def _original_log_lines(log_text):
    """
    Return non-empty original input lines.
    """

    return [
        line.strip()
        for line in str(log_text).splitlines()
        if line.strip()
    ]


# ---------------------------------------------------------------------------
# Contradiction detection
# ---------------------------------------------------------------------------

def _has_contradictory_authentication(
    log_text: str,
) -> bool:
    """
    Detect direct contradictory authentication observations.

    This intentionally remains narrow.
    """

    lines = _original_log_lines(
        log_text
    )

    has_success = any(
        _text_contains_any(
            line,
            (
                "login successful",
                "authentication successful",
                "authentication success",
                "login success",
                "authenticated successfully",
            ),
        )
        for line in lines
    )

    has_failure = any(
        _text_contains_any(
            line,
            (
                "login failed",
                "authentication failure",
                "authentication failed",
                "login failure",
                "login denied",
                "authentication denied",
            ),
        )
        for line in lines
    )

    return (
        has_success
        and has_failure
    )


# ---------------------------------------------------------------------------
# Compromise claim detection
# ---------------------------------------------------------------------------


def _has_claimed_compromise_without_telemetry(
    log_text: str,
) -> bool:
    """
    Detect compromise claims that lack supporting telemetry on the
    same line. Unrelated events must not validate a narrative claim.
    """
    text = str(log_text or "").lower()

    claim_markers = (
        "account was compromised",
        "account has been compromised",
        "system was compromised",
        "system has been compromised",
        "server was compromised",
        "server has been compromised",
        "we were compromised",
        "breach occurred",
        "we were breached",
        "account takeover",
        "attacker gained access",
        "compromise confirmed",
        "breach confirmed",
        "unauthorized access confirmed",
        "malware execution confirmed",
    )

    telemetry_markers = (
        "login successful",
        "authentication successful",
        "process executed",
        "command executed",
        "malware detected",
        "connection established",
        "file modified",
        "file created",
        "privilege escalation",
    )

    for line in text.splitlines():
        has_claim = any(
            marker in line
            for marker in claim_markers
        )

        if not has_claim:
            continue

        has_telemetry_on_same_line = any(
            marker in line
            for marker in telemetry_markers
        )

        if not has_telemetry_on_same_line:
            return True

    return False

def _append_data_quality_note(
    analysis,
    note,
):
    """
    Add a data-quality note without duplication.
    """

    notes = list(
        _analysis_field(
            analysis,
            "data_quality_notes",
            [],
        )
        or []
    )

    if note not in notes:
        notes.append(note)

    _set_analysis_field(
        analysis,
        "data_quality_notes",
        notes,
    )


def _ensure_summary_contains(
    analysis,
    statement,
):
    """
    Ensure the executive summary contains a deterministic
    safety/uncertainty statement.
    """

    summary = str(
        _analysis_field(
            analysis,
            "executive_summary",
            "",
        )
    ).strip()

    if statement.lower() in summary.lower():
        return

    if summary:
        summary = (
            f"{summary} {statement}"
        )
    else:
        summary = statement

    _set_analysis_field(
        analysis,
        "executive_summary",
        summary,
    )


def _lower_confidence_if_high(
    analysis,
):
    """
    Deterministically reduce HIGH confidence to MEDIUM when
    important uncertainty is detected.
    """

    confidence = str(
        _analysis_field(
            analysis,
            "confidence",
            "MEDIUM",
        )
    ).upper()

    if confidence == "HIGH":
        _set_analysis_field(
            analysis,
            "confidence",
            "MEDIUM",
        )


# ---------------------------------------------------------------------------
# Deterministic evidence safety
# ---------------------------------------------------------------------------


def _downgrade_unsupported_compromise_finding(finding):
    """
    Remove unsupported confirmed-compromise claims from a finding
    while preserving its useful investigative context.
    """
    title = str(
        _analysis_field(finding, "title", "")
    ).strip()

    description = str(
        _analysis_field(finding, "description", "")
    ).strip()

    attack_pattern = str(
        _analysis_field(finding, "attack_pattern", "")
    ).strip()

    unsafe_phrases = (
        "confirmed compromise",
        "confirmed breach",
        "compromise confirmed",
        "breach confirmed",
        "account was compromised",
        "account has been compromised",
        "system was compromised",
        "system has been compromised",
        "server was compromised",
        "attacker successfully accessed",
        "unauthorized access confirmed",
        "malware execution confirmed",
    )

    fields_to_check = (
        title,
        description,
        attack_pattern,
    )

    if not any(
        _text_contains_any(value, unsafe_phrases)
        for value in fields_to_check
    ):
        return

    if _text_contains_any(title, unsafe_phrases):
        _set_analysis_field(
            finding,
            "title",
            "Unverified compromise claim requires investigation",
        )

    if _text_contains_any(description, unsafe_phrases):
        _set_analysis_field(
            finding,
            "description",
            (
                "The supplied input contains a compromise claim, "
                "but the available evidence does not independently "
                "confirm that compromise occurred. Validate the "
                "claim against original authentication, endpoint, "
                "and network telemetry."
            ),
        )

    if _text_contains_any(attack_pattern, unsafe_phrases):
        _set_analysis_field(
            finding,
            "attack_pattern",
            "Potential compromise; attack pattern not yet verified",
        )

    severity = str(
        _analysis_field(finding, "severity", "")
    ).strip().upper()

    if severity in ("CRITICAL", "HIGH"):
        _set_analysis_field(
            finding,
            "severity",
            "MEDIUM",
        )

    confidence = str(
        _analysis_field(finding, "confidence", "")
    ).strip().upper()

    if confidence == "HIGH":
        _set_analysis_field(
            finding,
            "confidence",
            "LOW",
        )

    actions = _analysis_field(
        finding,
        "recommended_actions",
        [],
    )

    if isinstance(actions, list):
        safer_actions = [
            str(action).strip()
            for action in actions
            if str(action).strip()
        ]

        safer_actions.insert(
            0,
            "Validate the reported claim against original security telemetry before treating compromise as confirmed.",
        )

        _set_analysis_field(
            finding,
            "recommended_actions",
            list(dict.fromkeys(safer_actions)),
        )

def _enforce_evidence_safety(
    analysis,
    log_text,
):
    """
    Apply deterministic safety guardrails after AI analysis.

    This function prevents the LLM from silently ignoring:

    - contradictory authentication evidence
    - malformed timestamps
    - unsupported compromise claims
    """

    # ---------------------------------------------------------------
    # Contradictory authentication
    # ---------------------------------------------------------------

    if _has_contradictory_authentication(
        log_text
    ):
        _append_data_quality_note(
            analysis,
            "Contradictory authentication results are present "
            "and require verification.",
        )

        _lower_confidence_if_high(
            analysis
        )

        _ensure_summary_contains(
            analysis,
            "The input contains contradictory authentication "
            "results, so the authentication outcome requires "
            "verification.",
        )

    # ---------------------------------------------------------------
    # Malformed timestamps
    # ---------------------------------------------------------------

    malformed_timestamps = (
        find_malformed_timestamps(
            log_text
        )
    )

    if malformed_timestamps:
        note = (
            "Malformed timestamp detected: "
            + ", ".join(
                malformed_timestamps
            )
            + ". The event timing is uncertain and must not "
              "be inferred."
        )

        _append_data_quality_note(
            analysis,
            note,
        )

        _lower_confidence_if_high(
            analysis
        )

        _ensure_summary_contains(
            analysis,
            "The input contains a malformed timestamp, so the "
            "affected event cannot be reliably placed in time.",
        )

        # Make uncertainty explicit in findings too.
        findings = (
            _analysis_field(
                analysis,
                "findings",
                [],
            )
            or []
        )

        for finding in findings:
            description = str(
                _analysis_field(
                    finding,
                    "description",
                    "",
                )
            ).strip()

            if _text_contains_any(
                description,
                (
                    "malformed timestamp",
                    "invalid timestamp",
                    "timestamp uncertainty",
                    "cannot be reliably placed",
                    "cannot be reliably ordered",
                ),
            ):
                continue

            updated_description = (
                f"{description} "
                "The affected event has a malformed timestamp "
                "and therefore cannot be reliably placed in "
                "chronological order."
            ).strip()

            _set_analysis_field(
                finding,
                "description",
                updated_description,
            )

    # ---------------------------------------------------------------
    # Unsupported compromise claim
    # ---------------------------------------------------------------

    if _has_claimed_compromise_without_telemetry(
        log_text
    ):
        _append_data_quality_note(
            analysis,
            "Compromise is reported as a claim rather than "
            "verified by direct telemetry in the supplied input.",
        )

        summary = str(
            _analysis_field(
                analysis,
                "executive_summary",
                "",
            )
        )

        unsafe_phrases = (
            "confirmed compromise",
            "confirmed breach",
            "system was compromised",
            "account was compromised",
            "attacker successfully accessed",
        )

        if _text_contains_any(
            summary,
            unsafe_phrases,
        ):
            _set_analysis_field(
                analysis,
                "executive_summary",
                (
                    "The supplied input contains a reported "
                    "compromise claim, but the available evidence "
                    "does not independently verify that compromise "
                    "occurred. The claim should be validated against "
                    "original authentication, endpoint, or network "
                    "telemetry."
                ),
            )

        findings = (
            _analysis_field(
                analysis,
                "findings",
                [],
            )
            or []
        )

        for finding in findings:
            description = str(
                _analysis_field(
                    finding,
                    "description",
                    "",
                )
            )

            if not _text_contains_any(
                description,
                unsafe_phrases,
            ):
                continue

            _set_analysis_field(
                finding,
                "description",
                (
                    "The supplied input reports a possible "
                    "compromise, but does not independently "
                    "verify that compromise occurred."
                ),
            )

    # ------------------------------------------------------------------
    # Global compromise-safety guardrail
    # ------------------------------------------------------------------
    #
    # The LLM must not turn suspicious activity or narrative claims
    # into confirmed compromise unless the supplied input actually
    # contains direct evidence supporting that conclusion.

    if not _has_direct_compromise_evidence(log_text):
        analysis_text = _analysis_text(analysis)

        if _contains_unsupported_compromise_confirmation(
            analysis_text
        ):
            _append_data_quality_note(
                analysis,
                "The supplied evidence does not independently "
                "establish compromise; compromise language was "
                "downgraded to an unconfirmed interpretation.",
            )

            _set_analysis_field(
                analysis,
                "executive_summary",
                (
                    "The supplied evidence does not independently "
                    "confirm compromise. The observed activity or "
                    "reported claim requires further validation."
                ),
            )

            findings = (
                _analysis_field(
                    analysis,
                    "findings",
                    [],
                )
                or []
            )

            for finding in findings:
                description = str(
                    _analysis_field(
                        finding,
                        "description",
                        "",
                    )
                ).strip()

                _downgrade_unsupported_compromise_finding(
                    finding
                )

                if _contains_unsupported_compromise_confirmation(
                    description
                ):
                    _set_analysis_field(
                        finding,
                        "description",
                        (
                            "The supplied evidence indicates "
                            "suspicious or reported activity, but "
                            "does not independently confirm that "
                            "compromise occurred."
                        ),
                    )

            # Recalculate overall risk from the updated findings.
            severity_rank = {
                "INFO": 0,
                "LOW": 1,
                "MEDIUM": 2,
                "HIGH": 3,
                "CRITICAL": 4,
            }

            valid_severities = [
                str(
                    _analysis_field(
                        finding,
                        "severity",
                        "",
                    )
                ).upper()
                for finding in findings
            ]
            valid_severities = [
                severity
                for severity in valid_severities
                if severity in severity_rank
            ]

            if valid_severities:
                overall_risk = max(
                    valid_severities,
                    key=severity_rank.get,
                )
                _set_analysis_field(
                    analysis,
                    "overall_risk",
                    overall_risk,
                )

    return _correct_private_ip_labels(analysis, log_text)


# ---------------------------------------------------------------------------
# Investigation priorities
# ---------------------------------------------------------------------------

def _build_investigation_priorities(
    analysis,
):
    """
    Ensure findings produce investigation priorities.

    AI priorities are preferred. If none exist, derive conservative
    priorities from the findings.
    """

    existing = _analysis_field(
        analysis,
        "investigation_priority",
        None,
    )

    findings = _analysis_field(
        analysis,
        "findings",
        [],
    ) or []

    if existing:
        return existing

    priorities = []

    for finding in findings:
        raw_title = _analysis_field(
            finding,
            "title",
            "",
        )

        if raw_title is None:
            continue

        title = str(
            raw_title
        ).strip()

        if not title:
            continue

        priorities.append(
            "Investigate and validate the evidence "
            f"supporting: {title}"
        )

    if not priorities and findings:
        priorities.append(
            "Review and validate the available security "
            "findings against the original log evidence."
        )

    return priorities


# ---------------------------------------------------------------------------
# Main analysis function
# ---------------------------------------------------------------------------

def _analyze_log_request(
    log_text: str,
):
    """
    Analyze security logs using AI plus deterministic safeguards.

    Langfuse trace structure:

        security-log-analysis
        â”œâ”€â”€ prepare-input
        â”œâ”€â”€ ai-security-log-analysis
        â”œâ”€â”€ evidence-safety
        â”œâ”€â”€ build-deterministic-timeline
        â”œâ”€â”€ merge-ai-timeline
        â””â”€â”€ investigation-priorities

    AI is responsible for:

    - security interpretation
    - findings
    - risk assessment
    - confidence assessment
    - executive summary
    - investigation priorities

    Python is responsible for:

    - input validation
    - deterministic timestamp extraction
    - chronological ordering
    - preservation of original evidence
    - timeline severity normalization
    - malformed timestamp detection
    - contradiction detection
    - evidence-safety enforcement
    - investigation-priority fallback
    """

    # ---------------------------------------------------------------
    # 1. Prepare input
    # ---------------------------------------------------------------

    logs = _trace_step(
    "prepare-input",
    _prepare_logs,
    log_text,
    trace_input={
        "log_characters": len(log_text or ""),
        "log_lines": len((log_text or "").splitlines()),
    },
    trace_output=lambda value: {
        "log_characters": len(value),
        "log_lines": len(value.splitlines()),
    },
    )

    if not logs:
        raise ValueError(
            "No log data was provided for analysis."
        )

    if len(logs) < MIN_MEANINGFUL_CHARACTERS:
        raise ValueError(
            "The supplied input is too short to perform "
            "a meaningful security log analysis."
        )

    # ---------------------------------------------------------------
    # 2. AI analysis
    # ---------------------------------------------------------------

    analysis = analyze_logs_with_ai(
        logs
    )

    # ---------------------------------------------------------------
    # 3. Convert once to a plain dictionary
    # ---------------------------------------------------------------

    result = _analysis_to_dict(
        analysis
    )

    # ---------------------------------------------------------------
    # 4. Deterministic safety enforcement
    # ---------------------------------------------------------------

    before_safety = deepcopy(result)
    before_safety_snapshot = _analysis_trace_snapshot(before_safety)
    result = _trace_step(
        "evidence-safety",
        _enforce_evidence_safety,
        result,
        logs,
        trace_input={
            "log_excerpt": _trace_log_excerpt(logs),
            "analysis": before_safety_snapshot,
        },
        trace_output=lambda updated: {
            "changes": _analysis_trace_changes(before_safety, updated),
            "analysis": _analysis_trace_snapshot(updated),
        },
    )

    # ---------------------------------------------------------------
    # 5. Deterministic timeline
    # ---------------------------------------------------------------

    deterministic_timeline = _trace_step(
        "build-deterministic-timeline",
        _build_deterministic_timeline,
        logs,
        trace_input={"log_excerpt": _trace_log_excerpt(logs)},
        trace_output=_timeline_trace_rows,
    )


    ai_timeline = result.get(
        "timeline",
        [],
    )

    merged_timeline = _trace_step(
        "merge-ai-timeline",
        _merge_ai_timeline_with_deterministic_timeline,
        ai_timeline,
        deterministic_timeline,
        trace_input={
            "ai_timeline": _timeline_trace_rows(ai_timeline),
            "deterministic_timeline": _timeline_trace_rows(
                deterministic_timeline
            ),
        },
    )

    result["timeline"] = [
        _analysis_to_dict(event)
        for event in merged_timeline
    ]

    result["correlations"] = _trace_step(
        "correlate-authentication-events",
        _correlate_authentication_events,
        deterministic_timeline,
        logs,
        trace_input={
            "timeline_event_count": len(merged_timeline),
        },
        trace_output=lambda correlations: {
            "correlation_count": len(correlations),
            "event_counts": [
                correlation["event_count"]
                for correlation in correlations
            ],
        },
    )

    # ---------------------------------------------------------------
    # 6. Investigation priorities
    # ---------------------------------------------------------------

    result["investigation_priority"] = _trace_step(
        "investigation-priorities",
        _build_investigation_priorities,
        result,
        trace_input={
            "findings": [
                finding.get("title", "")
                for finding in result.get("findings", []) or []
                if isinstance(finding, dict)
            ],
            "ai_priorities": result.get("investigation_priority", []),
        },
        trace_output=lambda priorities: {
            "priorities": priorities,
            "priority_count": len(priorities),
        },
    )

    return result


def analyze_log(log_text: str):
    """Run one analysis as a single Langfuse root trace and flush it on exit."""

    try:
        client = get_langfuse_client()
        root_observation = client.start_as_current_observation(
            name="security-log-analysis",
            as_type="span",
        )
    except Exception:
        return _analyze_log_request(log_text)

    try:
        with root_observation as root:
            propagated_metadata = {
                "pipeline": "security-log-analysis",
                "provider": "groq",
                "model": str(
                    os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
                )[:200],
            }

            with propagate_attributes(metadata=propagated_metadata):
                try:
                    result = _analyze_log_request(log_text)
                except Exception as exc:
                    try:
                        root.update(
                            input={
                                "log_characters": len(log_text or ""),
                                "log_lines": len((log_text or "").splitlines()),
                            },
                            output={"status": "error"},
                            level="ERROR",
                            status_message=str(
                                mask_sensitive_data(data=str(exc))
                            )[:500],
                        )
                    except Exception:
                        pass
                    raise

                issues = _data_quality_issue_records(
                    result.get("data_quality_notes", [])
                )
                trace_output = dict(result)
                trace_output["data_quality_issues"] = issues

                try:
                    root.update(
                        input={
                            "log_characters": len(log_text or ""),
                            "log_lines": len((log_text or "").splitlines()),
                        },
                        output=mask_sensitive_data(data=trace_output),
                        metadata={
                            "input_characters": len(log_text or ""),
                            "input_lines": len((log_text or "").splitlines()),
                            "input_classification": result.get(
                                "input_classification"
                            ),
                            "overall_risk": result.get("overall_risk"),
                            "confidence": result.get("confidence"),
                            "finding_count": len(result.get("findings", []) or []),
                            "timeline_count": len(result.get("timeline", []) or []),
                            "data_quality_issue_count": len(issues),
                            "data_quality_issues": issues,
                        },
                    )
                except Exception:
                    pass

                return result
    finally:
        try:
            client.flush()
        except Exception:
            # Tracing must never replace an analysis result or its error.
            pass
