import json
from types import SimpleNamespace

import pytest

from app.analyzer import (
    _build_investigation_priorities,
    analyze_log,
)
from app.main import (
    analyze_logs,
    build_investigation_priorities,
    export_security_report,
    valid_severity,
)
from app.schemas import TimelineEvent


def _valid_llm_payload():
    return {
        "input_classification": "STRUCTURED",
        "data_quality_notes": [],
        "executive_summary": "Authentication activity was observed.",
        "overall_risk": "LOW",
        "confidence": "MEDIUM",
        "findings": [
            {
                "title": "MFA failure observed",
                "severity": "MEDIUM",
                "confidence": "LOW",
                "description": "An MFA failure was logged; success is not shown.",
                "evidence": ["MFA failure for user=alice"],
                "attack_pattern": "None identified",
                "recommended_actions": ["Correlate authentication records"],
            }
        ],
        "timeline": [],
        "investigation_priority": [],
    }


def _patch_llm_response(monkeypatch, content, usage=None):
    import app.llm as llm

    response = SimpleNamespace(
        choices=[
            SimpleNamespace(
                message=SimpleNamespace(
                    content=content,
                    refusal=None,
                )
            )
        ],
        usage=usage,
    )

    monkeypatch.setattr(llm, "GROQ_API_KEY", "test-key")
    monkeypatch.setattr(llm, "GROQ_MODEL", "test-model")
    monkeypatch.setattr(llm, "_create_client", lambda: object())
    monkeypatch.setattr(
        llm,
        "_request_ai_analysis",
        lambda client, log_text: response,
    )
    return llm


def test_ai_priorities_are_preserved():
    analysis = {
        "findings": [
            {"title": "Unusual login activity"},
        ],
        "investigation_priority": [
            "Review authentication logs",
            "Validate the source IP",
        ],
    }

    result = _build_investigation_priorities(analysis)

    assert result == [
        "Review authentication logs",
        "Validate the source IP",
    ]


def test_findings_without_ai_priorities_generate_conservative_priorities():
    analysis = {
        "findings": [
            {"title": "Unusual login activity"},
            {"title": "Multiple failed authentication attempts"},
        ],
        "investigation_priority": [],
    }

    result = _build_investigation_priorities(analysis)

    assert result == [
        "Investigate and validate the evidence supporting: "
        "Unusual login activity",
        "Investigate and validate the evidence supporting: "
        "Multiple failed authentication attempts",
    ]


def test_no_findings_produce_no_investigation_priorities():
    analysis = {
        "findings": [],
        "investigation_priority": [],
    }

    result = _build_investigation_priorities(analysis)

    assert result == []


def test_findings_without_valid_titles_use_safe_fallback():
    analysis = {
        "findings": [
            {"title": ""},
            {"title": None},
        ],
        "investigation_priority": [],
    }

    result = _build_investigation_priorities(analysis)

    assert result == [
        "Review and validate the available security "
        "findings against the original log evidence."
    ]


def test_allegation_produces_investigation_not_confirmed_incident():
    analysis = {
        "findings": [
            {
                "title": "User reports possible account compromise"
            }
        ],
        "investigation_priority": [],
    }

    result = _build_investigation_priorities(analysis)

    assert len(result) == 1
    assert "Investigate and validate" in result[0]
    assert "confirmed" not in result[0].lower()
    assert "compromised" not in result[0].lower()
    assert "reset credentials" not in result[0].lower()


def test_analyze_log_uses_ai_wrapper(monkeypatch):
    class StubAnalysis:
        def model_dump(self):
            return {
                "input_classification": "STRUCTURED",
                "data_quality_notes": [],
                "executive_summary": "summary",
                "overall_risk": "HIGH",
                "confidence": "MEDIUM",
                "findings": [],
                "timeline": [],
                "investigation_priority": [],
            }

    def fake_ai(log_text):
        assert log_text == "hello world"
        return StubAnalysis()

    monkeypatch.setattr(
        "app.analyzer.analyze_logs_with_ai",
        fake_ai,
    )

    result = analyze_log("hello world")

    assert result["executive_summary"] == "summary"
    assert result["overall_risk"] == "HIGH"
    assert result["findings"] == []


def test_analyze_log_rejects_empty_input():
    try:
        analyze_log("   ")
        assert False, "Expected ValueError for empty input"
    except ValueError as exc:
        assert "No log data was provided" in str(exc)


def test_main_analyze_logs_uses_requested_file_input(monkeypatch):
    def fake_analyze_log(log_text):
        return {
            "input_classification": "STRUCTURED",
            "data_quality_notes": [],
            "executive_summary": "ok",
            "overall_risk": "LOW",
            "confidence": "HIGH",
            "findings": [],
            "timeline": [],
            "investigation_priority": ["Review the log"],
        }

    monkeypatch.setattr(
        "app.main.analyze_log",
        fake_analyze_log,
    )

    result = analyze_logs(None, "manual logs")

    assert len(result) == 8
    assert "AI SECURITY ASSESSMENT" in result[2]
    assert "Review the log" in result[6]


def test_valid_severity_accepts_info():
    assert valid_severity("INFO") == "INFO"
    assert valid_severity("info") == "INFO"
    assert valid_severity(None) == "MEDIUM"


@pytest.mark.parametrize(
    ("log_text", "classification"),
    [
        (
            "2026-01-01 09:00:00 INFO auth login failed user=alice",
            "STRUCTURED",
        ),
        (
            "2026-01-01 09:00:00 INFO auth login failed\nAnalyst note: verify user",
            "MIXED",
        ),
        (
            "A user reports an unusual sign-in but has no supporting telemetry.",
            "UNSTRUCTURED",
        ),
    ],
)
def test_analysis_accepts_structured_messy_and_unstructured_input(
    monkeypatch,
    log_text,
    classification,
):
    def fake_ai(received_logs):
        assert received_logs == log_text
        payload = _valid_llm_payload()
        payload["input_classification"] = classification
        return payload

    monkeypatch.setattr(
        "app.analyzer.analyze_logs_with_ai",
        fake_ai,
    )

    result = analyze_log(log_text)

    assert result["input_classification"] == classification


def test_analyze_log_returns_serializable_timeline_with_source_line_numbers(
    monkeypatch,
):
    log_text = (
        "2026-01-01 10:00:00 INFO later event id=2 user=bob\n"
        "2026-01-01 09:00:00 WARN earlier event id=1 src_ip=10.0.0.2\n"
        "untimestamped original event user=alice"
    )

    monkeypatch.setattr(
        "app.analyzer.analyze_logs_with_ai",
        lambda _: _valid_llm_payload(),
    )

    result = analyze_log(log_text)
    timeline = result["timeline"]

    assert [event["timestamp"] for event in timeline] == [
        "2026-01-01 09:00:00",
        "2026-01-01 10:00:00",
        "Unknown",
    ]
    assert [event["line_number"] for event in timeline] == [2, 1, 3]
    assert all(
        {"timestamp", "event", "severity", "evidence", "line_number"}
        <= event.keys()
        for event in timeline
    )
    assert "earlier event id=1 src_ip=10.0.0.2" in timeline[0]["evidence"]
    assert "untimestamped original event user=alice" in timeline[2]["evidence"]
    json.dumps(result)


def test_malformed_timestamp_is_preserved_as_unknown_and_flagged(monkeypatch):
    log_text = "2026-99-44 77:88:99 WARN login failed user=alice"
    monkeypatch.setattr(
        "app.analyzer.analyze_logs_with_ai",
        lambda _: _valid_llm_payload(),
    )

    result = analyze_log(log_text)

    assert result["timeline"][0]["timestamp"] == "Unknown"
    assert result["timeline"][0]["line_number"] == 1
    assert log_text in result["timeline"][0]["evidence"]
    assert any(
        "Malformed timestamp" in note
        for note in result["data_quality_notes"]
    )


def test_private_ip_external_claim_is_corrected_without_changing_evidence(
    monkeypatch,
):
    log_text = "2026-01-01 09:00:00 WARN auth source_ip=10.0.0.5"
    payload = _valid_llm_payload()
    payload["executive_summary"] = "External IP address 10.0.0.5 was observed."
    payload["findings"][0]["description"] = (
        "Address 10.0.0.5 is an external address."
    )
    payload["findings"][0]["evidence"] = [log_text]
    monkeypatch.setattr(
        "app.analyzer.analyze_logs_with_ai",
        lambda _: payload,
    )

    result = analyze_log(log_text)

    assert "external" not in result["executive_summary"].lower()
    assert "external" not in result["findings"][0]["description"].lower()
    assert "private/internal" in result["executive_summary"].lower()
    assert result["findings"][0]["evidence"] == [log_text]
    assert any(
        "RFC1918 private IP" in note
        for note in result["data_quality_notes"]
    )


def test_pdf_timeline_evidence_column_contains_original_log(monkeypatch):
    captured = {}

    class CapturingDocument:
        def __init__(self, *args, **kwargs):
            pass

        def build(self, story, **kwargs):
            captured["story"] = story

    monkeypatch.setattr(
        "app.main.SimpleDocTemplate",
        CapturingDocument,
    )

    original_log = "2026-01-01 09:00:00 INFO login user=alice event_id=42"
    result = {
        "input_classification": "STRUCTURED",
        "overall_risk": "LOW",
        "confidence": "MEDIUM",
        "executive_summary": "A login event was observed.",
        "findings": [],
        "timeline": [
            {
                "timestamp": "2026-01-01 09:00:00",
                "event": "Observed log event.",
                "severity": "INFO",
                "evidence": f"Line 1: {original_log}",
                "line_number": 1,
            }
        ],
        "investigation_priority": [],
    }

    export_security_report(json.dumps(result))

    def collect_text(item):
        if hasattr(item, "getPlainText"):
            yield item.getPlainText()
        elif hasattr(item, "_cellvalues"):
            for row in item._cellvalues:
                for cell in row:
                    yield from collect_text(cell)
        elif isinstance(item, (list, tuple)):
            for child in item:
                yield from collect_text(child)

    report_text = " ".join(
        text
        for element in captured["story"]
        for text in collect_text(element)
    )

    assert "Evidence" in report_text
    assert original_log in report_text


def test_empty_findings_are_explicitly_not_applicable_in_dashboard():
    panel = build_investigation_priorities([], findings=[])

    assert "no investigation priorities are applicable" in panel.lower()
    assert "no findings were identified" in panel.lower()


def test_empty_uploaded_file_returns_graceful_error(tmp_path):
    empty_file = tmp_path / "empty.log"
    empty_file.write_text("", encoding="utf-8")

    outputs = analyze_logs(str(empty_file), "")

    assert len(outputs) == 8
    assert "No log input supplied" in json.loads(outputs[-1])["error"]


def test_invalid_upload_returns_graceful_error(tmp_path):
    outputs = analyze_logs(str(tmp_path / "missing.log"), "")

    assert len(outputs) == 8
    assert "No log input supplied" in json.loads(outputs[-1])["error"]


def test_ui_converts_provider_error_to_analysis_failure(monkeypatch):
    def fail_analysis(_):
        raise RuntimeError("Groq is unavailable")

    monkeypatch.setattr("app.main.analyze_log", fail_analysis)

    outputs = analyze_logs(None, "valid length manual security input")

    assert len(outputs) == 8
    error_result = json.loads(outputs[-1])
    assert error_result["status"] == "ANALYSIS FAILED"
    assert "Groq is unavailable" in error_result["error"]


def test_groq_unavailable_is_reported_without_request(monkeypatch):
    import app.llm as llm

    monkeypatch.setattr(llm, "GROQ_API_KEY", "")

    with pytest.raises(RuntimeError, match="analysis is unavailable"):
        llm.analyze_logs_with_ai("sufficiently long log input")


def test_invalid_ai_json_is_reported(monkeypatch):
    llm = _patch_llm_response(monkeypatch, "not valid json")

    with pytest.raises(RuntimeError, match="invalid JSON"):
        llm.analyze_logs_with_ai("sufficiently long log input")


def test_missing_ai_fields_are_reported(monkeypatch):
    llm = _patch_llm_response(monkeypatch, "{}")

    with pytest.raises(RuntimeError, match="does not match the SecurityAnalysis schema"):
        llm.analyze_logs_with_ai("sufficiently long log input")


@pytest.mark.parametrize(
    ("raw_text", "error_match", "validation_status"),
    [
        ("not valid JSON", "invalid JSON", "invalid_json"),
        ("{}", "does not match the SecurityAnalysis schema", "schema_invalid"),
    ],
)
def test_invalid_ai_response_is_recorded_as_error_generation(
    monkeypatch,
    raw_text,
    error_match,
    validation_status,
):
    calls = []

    class FakeGeneration:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

        def update(self, **kwargs):
            calls.append(kwargs)

    class FakeLangfuse:
        def start_as_current_observation(self, **kwargs):
            return FakeGeneration()

    llm = _patch_llm_response(monkeypatch, raw_text)
    monkeypatch.setattr(
        llm,
        "get_langfuse_client",
        lambda: FakeLangfuse(),
    )

    with pytest.raises(RuntimeError, match=error_match):
        llm.analyze_logs_with_ai("sufficiently long log input")

    error_update = next(
        update
        for update in calls
        if update.get("level") == "ERROR"
    )
    assert error_update["output"] == {"raw_model_text": raw_text}
    assert error_update["metadata"]["validation_status"] == validation_status
    assert error_update["status_message"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("severity", "NOT_A_SEVERITY"),
        ("confidence", "NOT_A_CONFIDENCE"),
        ("finding_confidence", "NOT_A_CONFIDENCE"),
    ],
)
def test_invalid_ai_severity_or_confidence_is_reported(
    monkeypatch,
    field,
    value,
):
    payload = _valid_llm_payload()
    if field == "finding_confidence":
        payload["findings"][0]["confidence"] = value
    elif field == "severity":
        payload["findings"][0][field] = value
    else:
        payload[field] = value

    llm = _patch_llm_response(
        monkeypatch,
        json.dumps(payload),
    )

    with pytest.raises(RuntimeError, match="does not match the SecurityAnalysis schema"):
        llm.analyze_logs_with_ai("sufficiently long log input")


@pytest.mark.parametrize(
    ("source_severity", "expected"),
    [
        ("WARN", "MEDIUM"),
        ("WARNING", "MEDIUM"),
        ("ERROR", "HIGH"),
        ("ERR", "HIGH"),
        ("DEBUG", "INFO"),
        ("NOTICE", "INFO"),
    ],
)
def test_timeline_schema_normalizes_source_severity_aliases(
    source_severity,
    expected,
):
    event = TimelineEvent(
        timestamp="Unknown",
        event="Observed log event",
        severity=source_severity,
        evidence="original log line",
    )

    assert event.severity == expected


def test_timeline_schema_rejects_unknown_severity():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        TimelineEvent(
            timestamp="Unknown",
            event="Observed log event",
            severity="NOT_A_SEVERITY",
            evidence="original log line",
        )


def test_langfuse_records_token_usage_without_raw_logs(monkeypatch):
    calls = []

    class FakeObservation:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

        def update(self, **kwargs):
            calls.append(("update", kwargs))

    class FakeLangfuse:
        def start_as_current_observation(self, **kwargs):
            calls.append(("start", kwargs))
            return FakeObservation()

    fake_client = FakeLangfuse()
    monkeypatch.setattr(
        "app.llm.get_langfuse_client",
        lambda: fake_client,
    )
    monkeypatch.setenv("LANGFUSE_REDACT_IPS", "true")
    monkeypatch.setenv("LANGFUSE_REDACT_USERNAMES", "true")
    usage = SimpleNamespace(
        prompt_tokens=120,
        completion_tokens=30,
        total_tokens=150,
    )
    llm = _patch_llm_response(
        monkeypatch,
        json.dumps(_valid_llm_payload()),
        usage=usage,
    )

    llm.analyze_logs_with_ai("sensitive user=alice token=do-not-trace")

    generation_call = next(
        kwargs
        for kind, kwargs in calls
        if kind == "update" and "usage_details" in kwargs
    )
    assert generation_call["model"] == "test-model"
    assert generation_call["usage_details"] == {
        "prompt_tokens": 120,
        "completion_tokens": 30,
        "total_tokens": 150,
    }
    input_call = next(
        kwargs
        for kind, kwargs in calls
        if kind == "update" and "input" in kwargs
    )
    assert "do-not-trace" not in repr(input_call)
    assert "alice" not in repr(input_call)


def test_langfuse_mask_always_redacts_secrets_and_configures_identity_masking(
    monkeypatch,
):
    from app.observability import mask_sensitive_data

    monkeypatch.setenv("LANGFUSE_REDACT_IPS", "true")
    monkeypatch.setenv("LANGFUSE_REDACT_USERNAMES", "true")
    data = {
        "log": "user=alice source_ip=192.168.1.12 password=hunter2 token=abc123",
        "api_key": "gsk_abcdefghijklmnopqrstuvwxyz",
    }

    masked = mask_sensitive_data(data=data)

    assert "alice" not in masked["log"]
    assert "192.168.1.12" not in masked["log"]
    assert "hunter2" not in masked["log"]
    assert "abc123" not in masked["log"]
    assert masked["api_key"] == "[REDACTED]"

    monkeypatch.setenv("LANGFUSE_REDACT_IPS", "false")
    monkeypatch.setenv("LANGFUSE_REDACT_USERNAMES", "false")
    configurable = mask_sensitive_data(data=data)
    assert "alice" in configurable["log"]
    assert "192.168.1.12" in configurable["log"]
    assert "hunter2" not in configurable["log"]


# ---------------------------------------------------------------------------
# DETERMINISTIC TIMELINE TESTS
# ---------------------------------------------------------------------------


def test_deterministic_timeline_extracts_timestamps():
    from app.analyzer import _build_deterministic_timeline

    logs = (
        "2026-01-01 09:00:00 INFO User login successful\n"
        "2026-01-01 10:00:00 WARN Failed login attempt\n"
    )

    timeline = _build_deterministic_timeline(logs)

    assert len(timeline) == 2
    assert timeline[0].timestamp == "2026-01-01 09:00:00"
    assert timeline[1].timestamp == "2026-01-01 10:00:00"


def test_deterministic_timeline_sorts_events_chronologically():
    from app.analyzer import _build_deterministic_timeline

    logs = (
        "2026-01-01 12:00:00 INFO Third event\n"
        "2026-01-01 09:00:00 INFO First event\n"
        "2026-01-01 10:00:00 INFO Second event\n"
    )

    timeline = _build_deterministic_timeline(logs)

    assert [
        event.timestamp
        for event in timeline
    ] == [
        "2026-01-01 09:00:00",
        "2026-01-01 10:00:00",
        "2026-01-01 12:00:00",
    ]


def test_deterministic_timeline_preserves_original_log_as_evidence():
    from app.analyzer import _build_deterministic_timeline

    log_line = (
        "2026-01-01 09:00:00 "
        "INFO User alice logged in from 10.0.0.15"
    )

    timeline = _build_deterministic_timeline(log_line)

    assert len(timeline) == 1
    assert log_line in timeline[0].evidence


def test_deterministic_timeline_handles_unknown_timestamp():
    from app.analyzer import _build_deterministic_timeline

    logs = (
        "This event has no timestamp\n"
        "2026-01-01 09:00:00 INFO Login event\n"
    )

    timeline = _build_deterministic_timeline(logs)

    assert len(timeline) == 2

    # Timestamped events come first.
    assert timeline[0].timestamp == "2026-01-01 09:00:00"

    # Untimestamped evidence is not silently discarded.
    assert timeline[1].timestamp == "Unknown"


def test_deterministic_timeline_assigns_conservative_severity():
    from app.analyzer import _build_deterministic_timeline

    logs = (
        "2026-01-01 09:00:00 INFO Normal activity\n"
        "2026-01-01 09:01:00 WARN Failed login attempt\n"
        "2026-01-01 09:02:00 ALERT Malware detected\n"
    )

    timeline = _build_deterministic_timeline(logs)

    assert timeline[0].severity == "INFO"
    assert timeline[1].severity == "MEDIUM"
    assert timeline[2].severity == "HIGH"


# ---------------------------------------------------------------------------
# TIMELINE / AI MERGE TESTS
# ---------------------------------------------------------------------------


def test_timeline_merge_does_not_attach_ai_interpretation_to_wrong_event():
    from app.analyzer import (
        _build_deterministic_timeline,
        _merge_ai_timeline_with_deterministic_timeline,
    )

    logs = (
        "2026-01-01 09:00:00 INFO auth First event\n"
        "2026-01-01 10:00:00 WARN auth Second event"
    )

    deterministic = _build_deterministic_timeline(logs)

    # Simulate an AI response that has reordered the events.
    ai_timeline = [
        {
            "timestamp": "2026-01-01 10:00:00",
            "event": "AI description of second event",
            "severity": "HIGH",
        },
        {
            "timestamp": "2026-01-01 09:00:00",
            "event": "AI description of first event",
            "severity": "INFO",
        },
    ]

    merged = _merge_ai_timeline_with_deterministic_timeline(
        ai_timeline,
        deterministic,
    )

    assert merged[0].timestamp == "2026-01-01 09:00:00"
    assert merged[0].event == "AI description of first event"
    assert merged[0].severity == "INFO"

    assert merged[1].timestamp == "2026-01-01 10:00:00"
    assert merged[1].event == "AI description of second event"
    assert merged[1].severity == "HIGH"


def test_timeline_merge_preserves_deterministic_events_when_ai_timeline_is_empty():
    from app.analyzer import (
        _build_deterministic_timeline,
        _merge_ai_timeline_with_deterministic_timeline,
    )

    logs = (
        "2026-01-01 09:00:00 INFO First event\n"
        "2026-01-01 10:00:00 WARN Second event"
    )

    deterministic = _build_deterministic_timeline(logs)

    merged = _merge_ai_timeline_with_deterministic_timeline(
        [],
        deterministic,
    )

    assert len(merged) == 2
    assert merged[0].timestamp == "2026-01-01 09:00:00"
    assert merged[1].timestamp == "2026-01-01 10:00:00"


def test_timeline_merge_does_not_guess_duplicate_or_unknown_timestamp_matches():
    from app.analyzer import (
        _build_deterministic_timeline,
        _merge_ai_timeline_with_deterministic_timeline,
    )

    deterministic = _build_deterministic_timeline(
        "2026-01-01 09:00:00 INFO first event\n"
        "2026-01-01 09:00:00 INFO second event\n"
        "untimestamped first\n"
        "untimestamped second"
    )
    ai_timeline = [
        {
            "timestamp": "2026-01-01 09:00:00",
            "event": "AI event that cannot be uniquely matched",
            "severity": "HIGH",
        },
        {
            "timestamp": "Unknown",
            "event": "AI event with unknown timestamp",
            "severity": "HIGH",
        },
    ]

    merged = _merge_ai_timeline_with_deterministic_timeline(
        ai_timeline,
        deterministic,
    )

    assert all(
        event.event != "AI event that cannot be uniquely matched"
        for event in merged
    )
    assert all(
        event.event != "AI event with unknown timestamp"
        for event in merged
    )
    assert [event.line_number for event in merged] == [1, 2, 3, 4]


# ---------------------------------------------------------------------------
# SECURITY CLASSIFICATION TESTS
# ---------------------------------------------------------------------------


def test_private_ip_is_not_classified_as_external():
    from app.analyzer import _is_private_ip

    assert _is_private_ip("10.0.0.15") is True
    assert _is_private_ip("192.168.1.20") is True
    assert _is_private_ip("172.16.0.10") is True
    assert _is_private_ip("172.31.255.255") is True
    assert _is_private_ip("172.15.255.255") is False
    assert _is_private_ip("172.32.0.0") is False
    assert _is_private_ip("100.64.0.1") is False
    assert _is_private_ip("not-an-ip") is False


def test_public_ip_is_not_classified_as_private():
    from app.analyzer import _is_private_ip

    assert _is_private_ip("8.8.8.8") is False
    assert _is_private_ip("1.1.1.1") is False


# ---------------------------------------------------------------------------
# EVIDENCE TRACEABILITY TESTS
# ---------------------------------------------------------------------------


def test_timeline_contains_line_number():
    from app.analyzer import _build_deterministic_timeline

    logs = (
        "2026-01-01 09:00:00 INFO First event\n"
        "2026-01-01 10:00:00 WARN Second event"
    )

    timeline = _build_deterministic_timeline(logs)

    assert hasattr(timeline[0], "line_number")
    assert timeline[0].line_number == 1
    assert timeline[1].line_number == 2


def test_timeline_evidence_contains_original_log_line():
    from app.analyzer import _build_deterministic_timeline

    log_line = (
        "2026-01-01 09:00:00 "
        "INFO user=alice src_ip=10.0.0.15 login"
    )

    timeline = _build_deterministic_timeline(log_line)

    assert log_line in timeline[0].evidence


# ---------------------------------------------------------------------------
# INPUT / ERROR HANDLING TESTS
# ---------------------------------------------------------------------------


def test_empty_findings_are_valid():
    analysis = {
        "findings": [],
        "investigation_priority": [],
    }

    result = _build_investigation_priorities(analysis)

    assert result == []


def test_invalid_severity_falls_back_safely():
    assert valid_severity("NOT_A_SEVERITY") == "MEDIUM"
    assert valid_severity("UNKNOWN") == "MEDIUM"


def test_case_insensitive_severity_is_supported():
    assert valid_severity("critical") == "CRITICAL"
    assert valid_severity("high") == "HIGH"
    assert valid_severity("medium") == "MEDIUM"
    assert valid_severity("low") == "LOW"
    assert valid_severity("info") == "INFO"


def test_system_prompt_treats_mfa_and_unusual_login_as_anomalies():
    from app.llm import SYSTEM_PROMPT

    prompt = " ".join(SYSTEM_PROMPT.split())

    assert "MFA failure" in prompt
    assert "not, by itself, evidence that an attack succeeded" in prompt
    assert "Use lower confidence when important context is missing" in prompt
    assert "172.16.0.0/12" in prompt
