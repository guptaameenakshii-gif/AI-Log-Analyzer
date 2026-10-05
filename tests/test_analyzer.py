from app.analyzer import analyze_log
from app.main import analyze_logs, valid_severity


def test_analyze_log_uses_ai_wrapper(monkeypatch):
    class StubAnalysis:
        def model_dump(self):
            return {
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

    monkeypatch.setattr("app.analyzer.analyze_logs_with_ai", fake_ai)

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
            "executive_summary": "ok",
            "overall_risk": "LOW",
            "confidence": "HIGH",
            "findings": [],
            "timeline": [],
            "investigation_priority": ["Review the log"],
        }

    monkeypatch.setattr("app.main.analyze_log", fake_analyze_log)

    result = analyze_logs(None, "manual logs")

    assert len(result) == 8
    assert "AI SECURITY ASSESSMENT" in result[2]
    assert "Review the log" in result[6]


def test_valid_severity_accepts_info():
    assert valid_severity("INFO") == "INFO"
    assert valid_severity("info") == "INFO"
    assert valid_severity(None) == "MEDIUM"
