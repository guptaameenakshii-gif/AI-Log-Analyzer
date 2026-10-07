import re
from datetime import datetime
import ipaddress

from langfuse import get_client

from .llm import analyze_logs_with_ai
from .schemas import TimelineEvent
from .timeline import (
    classify_timeline_severity,
    extract_timeline_candidates,
    find_malformed_timestamps,
    sort_timeline_candidates,
)


MAX_LOG_CHARACTERS = 240_000
MIN_MEANINGFUL_CHARACTERS = 10


def _trace_step(name, operation, *args, **kwargs):
    """Run one operation as a child span when a request trace is active."""

    try:
        observation = get_client().start_as_current_observation(
            name=name,
            as_type="span",
        )
    except Exception:
        return operation(*args, **kwargs)

    with observation:
        return operation(*args, **kwargs)


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


def _build_deterministic_timeline(log_text: str) -> list[TimelineEvent]:
    """
    Build the security timeline deterministically from the original
    log input.

    The LLM is not responsible for deciding chronological order.

    Rules:
    - timestamps are extracted in Python;
    - timestamped events are sorted chronologically;
    - events without timestamps are retained and placed last;
    - the original log line is preserved as evidence;
    - line numbers are preserved for traceability;
    - severity is conservative and based only on observable wording;
    - this timeline is not itself a security verdict.
    """

    candidates = extract_timeline_candidates(log_text)
    candidates = sort_timeline_candidates(candidates)

    timeline = []

    for candidate in candidates:
        original_log = candidate["original_log"]

        timestamp = candidate["timestamp"]

        severity = classify_timeline_severity(
            original_log
        )

        # Keep the event description deliberately factual.
        # Do not turn an authentication failure into a confirmed
        # attack or incident.
        if timestamp == "Unknown":
            event_description = (
                "Observed log event without a reliable timestamp."
            )
        else:
            event_description = (
                "Observed log event at the recorded timestamp."
            )

        timeline.append(
            TimelineEvent(
                timestamp=timestamp,
                event=event_description,
                severity=severity,
                evidence=(
                    f"Line {candidate['line_number']}: "
                    f"{original_log}"
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

    Python remains authoritative for:

    - ordering
    - timestamps
    - original evidence

    AI may provide:

    - event description
    - severity

    AI events are matched by timestamp.
    """

    if not deterministic_timeline:
        return ai_timeline or []

    ai_timeline = ai_timeline or []

    ai_by_timestamp = {}
    deterministic_counts = {}

    for event in deterministic_timeline:
        timestamp = _get_ai_timeline_value(
            event,
            "timestamp",
            "Unknown",
        )
        deterministic_counts[timestamp] = (
            deterministic_counts.get(timestamp, 0) + 1
        )

    for ai_event in ai_timeline:
        timestamp = _get_ai_timeline_value(
            ai_event,
            "timestamp",
            None,
        )

        if timestamp is None:
            continue

        timestamp = str(timestamp).strip()

        if not timestamp:
            continue

        ai_by_timestamp.setdefault(timestamp, []).append(ai_event)

    merged = []

    for event in deterministic_timeline:
        timestamp = _get_ai_timeline_value(
            event,
            "timestamp",
            "Unknown",
        )

        matching_ai_events = ai_by_timestamp.get(timestamp, [])
        ai_event = (
            matching_ai_events[0]
            if timestamp != "Unknown"
            and deterministic_counts.get(timestamp) == 1
            and len(matching_ai_events) == 1
            else None
        )

        ai_description = _get_ai_timeline_value(
            ai_event,
            "event",
            "",
        )

        ai_severity = _get_ai_timeline_value(
            ai_event,
            "severity",
            None,
        )

        merged.append(
            TimelineEvent(
                timestamp=timestamp,
                event=(
                    ai_description
                    or _get_ai_timeline_value(
                        event,
                        "event",
                        "",
                    )
                ),
                severity=_normalize_severity(
                    ai_severity,
                    fallback=_get_ai_timeline_value(
                        event,
                        "severity",
                        "INFO",
                    ),
                ),
                evidence=_get_ai_timeline_value(
                    event,
                    "evidence",
                    "",
                ),
                line_number=_get_ai_timeline_value(
                    event,
                    "line_number",
                    None,
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
    Determine whether the supplied input contains reasonably direct
    telemetry supporting confirmed compromise.

    This is intentionally conservative.
    """
    text = str(log_text or "").lower()

    direct_indicators = (
        "unauthorized access confirmed",
        "account takeover confirmed",
        "compromise confirmed",
        "breach confirmed",
        "attacker successfully accessed",
        "malware execution confirmed",
    )

    return any(
        indicator in text
        for indicator in direct_indicators
    )


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
    Detect narrative compromise claims without direct telemetry.

    This does NOT assert that the compromise occurred.
    """

    text = str(
        log_text or ""
    ).lower()

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

    has_claim = any(
        marker in text
        for marker in claim_markers
    )

    has_telemetry = any(
        marker in text
        for marker in telemetry_markers
    )

    return (
        has_claim
        and not has_telemetry
    )


# ---------------------------------------------------------------------------
# Data-quality helpers
# ---------------------------------------------------------------------------

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

            summary = str(
                _analysis_field(
                    analysis,
                    "executive_summary",
                    "",
                )
            ).strip()

            summary = (
                "The supplied evidence does not independently "
                "confirm compromise. The observed activity or "
                "reported claim requires further validation."
            )

            _set_analysis_field(
                analysis,
                "executive_summary",
                summary,
            )

            for finding in (
                _analysis_field(
                    analysis,
                    "findings",
                    [],
                )
                or []
            ):
                description = str(
                    _analysis_field(
                        finding,
                        "description",
                        "",
                    )
                ).strip()

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
        ├── prepare-input
        ├── ai-security-log-analysis
        ├── evidence-safety
        ├── build-deterministic-timeline
        ├── merge-ai-timeline
        └── investigation-priorities

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

    result = _trace_step(
        "evidence-safety",
        _enforce_evidence_safety,
        result,
        logs,
    )

    # ---------------------------------------------------------------
    # 5. Deterministic timeline
    # ---------------------------------------------------------------

    deterministic_timeline = _trace_step(
        "build-deterministic-timeline",
        _build_deterministic_timeline,
        logs,
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
    )
    result["timeline"] = [
        _analysis_to_dict(event)
        for event in merged_timeline
    ]

    # ---------------------------------------------------------------
    # 6. Investigation priorities
    # ---------------------------------------------------------------

    result["investigation_priority"] = _trace_step(
        "investigation-priorities",
        _build_investigation_priorities,
        result,
    )

    # ---------------------------------------------------------------
    # 7. Add final result to the root Langfuse observation
    # ---------------------------------------------------------------

    try:
        from langfuse import get_client

        get_client().update_current_span(
            input={
                "log_characters": len(logs),
                "log_lines": len(logs.splitlines()),
            },
            output={"status": "completed"},
            metadata={
                "input_characters": len(logs),
                "input_lines": len(
                    logs.splitlines()
                ),
                "input_classification": result.get(
                    "input_classification"
                ),
                "overall_risk": result.get(
                    "overall_risk"
                ),
                "confidence": result.get(
                    "confidence"
                ),
                "finding_count": len(
                    result.get(
                        "findings",
                        [],
                    )
                    or []
                ),
                "timeline_count": len(
                    result.get(
                        "timeline",
                        [],
                    )
                    or []
                ),
                "data_quality_issue_count": len(
                    result.get(
                        "data_quality_notes",
                        [],
                    )
                    or []
                ),
            },
        )

    except Exception:
        # Langfuse telemetry must never break the security analysis.
        pass

    return result


def analyze_log(log_text: str):
    """Run one analysis as a single Langfuse root trace and flush it on exit."""

    try:
        client = get_client()
        root_observation = client.start_as_current_observation(
            name="security-log-analysis",
            as_type="span",
        )
    except Exception:
        return _analyze_log_request(log_text)

    try:
        with root_observation:
            return _analyze_log_request(log_text)
    finally:
        try:
            client.flush()
        except Exception:
            # Tracing must never replace an analysis result or its error.
            pass
