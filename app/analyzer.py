from .llm import analyze_logs_with_ai


MAX_LOG_CHARACTERS = 240_000
CHUNK_CHARACTERS = 20_000
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


def _analysis_to_dict(analysis):
    """
    Convert validated Pydantic analysis into a plain dictionary
    suitable for the dashboard.
    """

    return analysis.model_dump()


def analyze_log(log_text: str):
    """
    AI-first security log analysis.

    The AI classifies the input as structured, unstructured,
    mixed, or insufficient and performs evidence-grounded analysis.

    Deterministic validation happens before the AI call so that:
    - empty input is rejected
    - oversized input is rejected
    - obviously unusable input is rejected
    - the original log content is preserved
    - security interpretation remains the responsibility of the AI
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

    return _analysis_to_dict(analysis)
