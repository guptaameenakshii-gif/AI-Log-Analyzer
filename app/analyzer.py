from .llm import analyze_logs_with_ai
from .schemas import TimelineEvent
from .timeline import (
    classify_timeline_severity,
    extract_timeline_candidates,
    sort_timeline_candidates,
)


MAX_LOG_CHARACTERS = 240_000
MIN_MEANINGFUL_CHARACTERS = 10


def _prepare_logs(log_text: str) -> str:
    """
    Prepare raw input for AI analysis.

    This function performs input validation only.
    It does not perform security interpretation.
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


def _build_deterministic_timeline(log_text: str):
    """
    Extract and chronologically sort timestamps from the original logs.

    Timestamp extraction and ordering are deterministic and performed
    in Python so that timeline ordering does not depend entirely on
    the LLM.
    """

    candidates = extract_timeline_candidates(log_text)
    candidates = sort_timeline_candidates(candidates)

    timeline = []

    for candidate in candidates:
        original_log = candidate["original_log"]

        timeline.append(
            {
                "timestamp": candidate["timestamp"],
                "event": original_log,
                "severity": classify_timeline_severity(original_log),
                "evidence": (
                    f"Line {candidate['line_number']}: "
                    f"{original_log}"
                ),
            }
        )

    return timeline


def _get_ai_timeline_value(
    ai_event,
    field_name: str,
    default=None,
):
    """
    Safely read a timeline field from either a Pydantic model
    or a dictionary.

    The AI schema normally returns TimelineEvent Pydantic objects,
    while tests or compatibility callers may provide dictionaries.
    """

    if ai_event is None:
        return default

    if isinstance(ai_event, dict):
        return ai_event.get(field_name, default)

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
    Merge AI timeline interpretation with the deterministic timeline.

    Python remains authoritative for:

    - chronological ordering
    - original timestamps
    - original evidence

    AI information may provide a more useful event description and
    severity when available.

    Supports both Pydantic TimelineEvent objects and dictionaries.
    """

    if not deterministic_timeline:
        return ai_timeline or []

    ai_timeline = ai_timeline or []
    merged = []

    for index, event in enumerate(deterministic_timeline):
        ai_event = (
            ai_timeline[index]
            if index < len(ai_timeline)
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
                timestamp=event["timestamp"],
                event=(
                    ai_description
                    or event["event"]
                ),
                severity=(
                    ai_severity
                    or event["severity"]
                ),
                evidence=event["evidence"],
            )
        )

    return merged


def _build_investigation_priorities(analysis):
    """
    Ensure findings produce structured investigation priorities.

    AI-generated priorities are preferred. If the model returns none,
    derive conservative priorities from the findings without inventing
    new security activity.
    """

    if isinstance(analysis, dict):
        existing = analysis.get(
            "investigation_priority"
        )
        findings = analysis.get(
            "findings",
            [],
        )
    else:
        existing = getattr(
            analysis,
            "investigation_priority",
            None,
        )
        findings = getattr(
            analysis,
            "findings",
            [],
        )

    if existing:
        return existing

    priorities = []

    for finding in findings:
        if isinstance(finding, dict):
            title = str(
                finding.get(
                    "title",
                    "",
                )
            ).strip()
        else:
            title = str(
                getattr(
                    finding,
                    "title",
                    "",
                )
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


def _analysis_to_dict(analysis):
    """
    Convert validated Pydantic analysis into a plain dictionary
    suitable for the dashboard.
    """

    if analysis is None:
        return {}

    if isinstance(analysis, dict):
        return dict(analysis)

    if hasattr(analysis, "model_dump"):
        return analysis.model_dump()

    return dict(analysis)


def analyze_log(log_text: str):
    """
    AI-first security log analysis with deterministic timeline extraction.

    The AI remains responsible for security interpretation.

    Python is responsible for:

    - input validation
    - timestamp extraction
    - chronological ordering
    - preserving original log evidence
    - ensuring investigation priorities are available when findings exist
    """

    logs = _prepare_logs(log_text)

    if not logs:
        raise ValueError(
            "No log data was provided for analysis."
        )

    if len(logs) < MIN_MEANINGFUL_CHARACTERS:
        raise ValueError(
            "The supplied input is too short to perform "
            "a meaningful security log analysis."
        )

    analysis = analyze_logs_with_ai(logs)

    deterministic_timeline = _build_deterministic_timeline(
        logs
    )

    if isinstance(analysis, dict):
        ai_timeline = analysis.get(
            "timeline",
            [],
        )

        analysis["timeline"] = (
            _merge_ai_timeline_with_deterministic_timeline(
                ai_timeline,
                deterministic_timeline,
            )
        )

        analysis["investigation_priority"] = (
            _build_investigation_priorities(
                analysis
            )
        )

        return _analysis_to_dict(analysis)

    ai_timeline = getattr(
        analysis,
        "timeline",
        [],
    )

    analysis.timeline = (
        _merge_ai_timeline_with_deterministic_timeline(
            ai_timeline,
            deterministic_timeline,
        )
    )

    analysis.investigation_priority = (
        _build_investigation_priorities(
            analysis
        )
    )

    return _analysis_to_dict(analysis)
