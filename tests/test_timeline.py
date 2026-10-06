from app.timeline import (
    extract_timestamp,
    extract_timeline_candidates,
    sort_timeline_candidates,
)


def test_extract_timestamp():
    result = extract_timestamp(
        "2026-01-02 10:30:45 login failed"
    )

    assert result is not None
    assert result["original"] == "2026-01-02 10:30:45"
    assert result["normalized"] == "2026-01-02T10:30:45"


def test_extract_timestamp_returns_none_for_missing_timestamp():
    result = extract_timestamp(
        "login failed for user admin"
    )

    assert result is None


def test_extract_timestamp_rejects_invalid_timestamp():
    result = extract_timestamp(
        "2026-99-44 77:88:99 invalid timestamp"
    )

    assert result is None


def test_timeline_is_sorted_chronologically():
    logs = (
        "2026-01-03 12:00:00 third event\n"
        "2026-01-01 09:00:00 first event\n"
        "2026-01-02 10:00:00 second event"
    )

    candidates = extract_timeline_candidates(logs)
    timeline = sort_timeline_candidates(candidates)

    assert [
        event["timestamp"]
        for event in timeline
    ] == [
        "2026-01-01 09:00:00",
        "2026-01-02 10:00:00",
        "2026-01-03 12:00:00",
    ]


def test_timeline_preserves_line_numbers_and_original_log():
    logs = (
        "2026-01-01 09:00:00 login successful\n"
        "something without timestamp"
    )

    candidates = extract_timeline_candidates(logs)

    assert candidates[0]["line_number"] == 1
    assert (
        candidates[0]["original_log"]
        == "2026-01-01 09:00:00 login successful"
    )

    assert candidates[1]["line_number"] == 2
    assert candidates[1]["timestamp"] == "Unknown"


def test_unknown_timestamps_are_sorted_last():
    logs = (
        "something without timestamp\n"
        "2026-01-01 09:00:00 login successful\n"
        "another unknown event"
    )

    candidates = extract_timeline_candidates(logs)
    timeline = sort_timeline_candidates(candidates)

    assert timeline[0]["timestamp"] == "2026-01-01 09:00:00"
    assert timeline[1]["timestamp"] == "Unknown"
    assert timeline[2]["timestamp"] == "Unknown"

from app.timeline import classify_timeline_severity


def test_failed_login_is_medium_severity():
    assert (
        classify_timeline_severity(
            "2026-09-25 11:00:00 WARN auth Failed login for root"
        )
        == "MEDIUM"
    )


def test_malware_detection_is_high_severity():
    assert (
        classify_timeline_severity(
            "2026-09-25 11:00:00 ERROR malware detected"
        )
        == "HIGH"
    )


def test_normal_successful_login_is_info():
    assert (
        classify_timeline_severity(
            "2026-09-25 11:00:10 INFO auth Successful login for root"
        )
        == "INFO"
    )

def test_extract_timestamp_supports_utc_timezone():
    result = extract_timestamp(
        "2026-01-02T10:30:45Z login failed"
    )

    assert result is not None
    assert result["original"] == "2026-01-02T10:30:45Z"
    assert result["normalized"] == "2026-01-02T10:30:45+00:00"


def test_extract_timestamp_supports_timezone_offset():
    result = extract_timestamp(
        "2026-01-02T10:30:45+05:30 login failed"
    )

    assert result is not None
    assert result["original"] == "2026-01-02T10:30:45+05:30"


def test_timezone_aware_timestamps_can_be_sorted():
    logs = (
        "2026-01-02T10:00:00Z first event\n"
        "2026-01-02T16:00:00+05:30 second event"
    )

    candidates = extract_timeline_candidates(logs)
    timeline = sort_timeline_candidates(candidates)

    assert [
        event["timestamp"]
        for event in timeline
    ] == [
        "2026-01-02T10:00:00Z",
        "2026-01-02T16:00:00+05:30",
    ]


def test_timezone_aware_and_naive_timestamps_do_not_crash():
    logs = (
        "2026-01-02T10:00:00Z timezone event\n"
        "2026-01-02 11:00:00 naive event"
    )

    candidates = extract_timeline_candidates(logs)

    timeline = sort_timeline_candidates(candidates)

    assert len(timeline) == 2
