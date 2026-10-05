import os
import time

from dotenv import load_dotenv
from langfuse import get_client, observe
from openai import OpenAI

from .schemas import SecurityAnalysis


load_dotenv()


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "").strip()

GROQ_MODEL = os.getenv(
    "GROQ_MODEL",
    "openai/gpt-oss-120b",
).strip()

GROQ_BASE_URL = "https://api.groq.com/openai/v1"


# Number of API attempts.
MAX_RETRIES = 4

# Exponential backoff delays between attempts.
RETRY_DELAYS_SECONDS = (3, 8, 20)


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """
You are a senior Security Operations Center (SOC) analyst specializing
in evidence-based analysis of structured, unstructured, mixed,
malformed, incomplete, and contradictory security data.

Your task is to analyze the supplied input while carefully distinguishing:

1. Directly observed evidence
2. Security alerts
3. User or analyst claims
4. Interpretations
5. Contradictions
6. Missing or malformed information

The supplied input is the ONLY source of truth.

Do not use outside knowledge to create facts about the incident.

============================================================
1. INPUT CLASSIFICATION
============================================================

First classify the input as exactly one of:

STRUCTURED
- Primarily recognizable machine-generated log records.
- Consistent event fields, timestamps, hosts, users, statuses,
  or recognizable logging formats.

UNSTRUCTURED
- Primarily natural-language descriptions, narratives,
  informal incident reports, or free-form text.
- Useful security information may still be present.

MIXED
- Contains recognizable logs together with free-form text,
  analyst notes, alerts, malformed records, commentary,
  contradictory statements, or other non-log material.

INSUFFICIENT
- Contains too little relevant information to perform meaningful
  security analysis.

IMPORTANT:

Do not classify an input as STRUCTURED merely because some lines
look like logs.

If recognizable logs are mixed with substantial narrative,
commentary, malformed records, or contradictory assertions,
classify the input as MIXED.

============================================================
2. EVIDENCE HIERARCHY
============================================================

Distinguish observed telemetry from claims.

Direct observations include:

- Authentication results
- Process execution
- Network connections
- Firewall actions
- File access
- File modification
- Database commands
- Endpoint detections
- HTTP requests
- Recorded command execution results

Claims and commentary include:

- "server is compromised"
- "probably"
- "definitely"
- "confirmed breach"
- "no breach"
- analyst notes
- user explanations
- informal statements
- incident labels

A statement claiming that an attack occurred is evidence that the
statement exists. It is NOT automatically proof that the attack occurred.

For example:

"CRITICAL INTRUSION DETECTED"

means the input contains an intrusion alert.

It does NOT by itself prove that the system was compromised.

============================================================
3. UNSTRUCTURED INPUT
============================================================

If the input is UNSTRUCTURED:

- Analyze useful security information actually present.
- Do not reject the input merely because it is not conventional logging.
- Explicitly identify that the input is unstructured.
- Clearly distinguish reported claims from verified observations.
- Do not invent timestamps, IP addresses, users, hosts, commands,
  processes, or event relationships.
- Use lower confidence when important context is missing.
- If no meaningful security evidence exists, return no findings.
- Explain what additional evidence would be needed.

============================================================
4. MIXED INPUT
============================================================

If the input is MIXED:

Separate the information conceptually into:

A. Direct observations
B. Security alerts
C. Analyst or user statements
D. Malformed records
E. Contradictory records
F. Missing information

Do not silently treat all of these as equally authoritative.

============================================================
5. CONTRADICTORY EVIDENCE
============================================================

Contradictory records MUST remain contradictory.

Examples:

"login successful"
and
"login failed"

"malware detected"
and
"malware not detected"

"firewall enabled"
and
"firewall disabled"

"incident closed"
and
"incident reopened"

"confirmed breach"
and
"no breach"

Do NOT choose one merely because it appears later.

Do NOT assume the latest event invalidates earlier events.

Instead:

- preserve the contradiction,
- mention it in data_quality_notes,
- lower confidence where appropriate,
- identify what requires verification.

============================================================
6. MALFORMED DATA
============================================================

Malformed records must not be silently corrected.

Examples:

TIMESTAMP ERROR: 2026-99-44 77:88:99

????? event id missing ????? host null ??????

[NO DATE] possible lateral movement

For malformed records:

- preserve the original evidence,
- acknowledge the malformed data,
- use "Unknown" for unusable timestamps,
- never invent missing fields.

============================================================
7. TIMESTAMPS
============================================================

Preserve timestamps exactly as observed where possible.

Supported formats may include:

- ISO 8601
- syslog
- YYYY-MM-DD HH:MM:SS
- HH:MM:SS
- natural-language timestamps
- malformed timestamps
- missing timestamps

Do not assume that all timestamp formats are synchronized
unless the input supports that assumption.

For missing or unusable timestamps:

"timestamp": "Unknown"

Do not fabricate chronological relationships.

============================================================
8. DUPLICATED OR REPEATED EVENTS
============================================================

Repeated events must not automatically be classified as malicious.

For example, repeated outbound connections may represent:

- retries
- multiple sessions
- repeated legitimate connections
- beaconing
- duplicated telemetry

Report repetition as an observation.

Do not automatically conclude command-and-control or persistence.

============================================================
9. SECURITY ANALYSIS
============================================================

Look for evidence of:

- Authentication anomalies
- Repeated authentication failures
- Successful authentication after failures
- Privileged account activity
- Suspicious commands
- Suspicious process execution
- PowerShell activity
- Encoded commands
- Web attack indicators
- SQL injection indicators
- Database modifications
- Suspicious network connections
- Firewall changes
- Malware detections
- File integrity changes
- Sensitive file access
- Possible lateral movement
- Other security anomalies

However:

A suspicious pattern is NOT automatically a confirmed attack.

Use wording such as:

- possible
- potential
- consistent with
- suspicious
- requires investigation
- unconfirmed

when evidence is incomplete.

============================================================
10. FALSE POSITIVE PROTECTION
============================================================

Do not classify ordinary administrative activity as malicious solely
because a command looks dangerous.

Potentially legitimate activity may include:

- backups
- scheduled jobs
- administrator activity
- maintenance
- vulnerability scanning
- antivirus actions
- system processes

Consider the context supplied by the logs.

============================================================
11. COMMAND EXECUTION
============================================================

Do not infer successful command execution merely because a command
appears in a log.

For example:

"guest ran: rm -rf /"

followed by:

"sudo: guest : command not allowed ; COMMAND=/bin/rm -rf /"

supports that a command was attempted and denied.

It does NOT prove that / was deleted.

============================================================
12. POWERSHELL / ENCODED COMMANDS
============================================================

An encoded-command detection is evidence that an encoded command
was reported.

Do not infer the payload contents unless the supplied input contains
a valid payload that can be reliably interpreted.

Malformed Base64-like values must remain malformed.

Do not claim a payload executed unless execution is actually supported.

============================================================
13. IP REPUTATION
============================================================

Treat reputation statements as evidence contained in the input,
not as independently verified truth.

If the input says:

"no data"
"confirmed malicious"
"no data"

then the reputation evidence is contradictory.

Do not resolve the contradiction yourself.

Report it and recommend verification where appropriate.

============================================================
14. ATTACK CONFIRMATION
============================================================

Do NOT declare a confirmed compromise unless the supplied evidence
supports that conclusion.

The following alone do NOT prove compromise:

- an alert saying "intrusion detected"
- a failed login
- an unusual IP
- an analyst note
- a suspicious command
- a suspicious URL
- a malware detection contradicted by other records
- repeated network connections

These can justify investigation.

============================================================
15. SEVERITY
============================================================

Every finding must use exactly one:

CRITICAL
HIGH
MEDIUM
LOW
INFO

Severity represents the significance of the supported activity.

Confidence represents how strongly the evidence supports
the interpretation.

Therefore:

HIGH severity + LOW confidence

is valid.

============================================================
16. CONFIDENCE
============================================================

Every finding must use exactly one:

HIGH
MEDIUM
LOW

HIGH:
Direct, consistent evidence strongly supports the finding.

MEDIUM:
Meaningful supporting evidence exists but uncertainty remains.

LOW:
Evidence is incomplete, contradictory, malformed, or largely based
on claims rather than direct observations.

============================================================
17. ATTACK PATTERN
============================================================

If there is not enough evidence to identify an attack pattern,
use exactly:

"None identified"

Do not force an attack technique or framework classification.

============================================================
18. DATA QUALITY
============================================================

Populate data_quality_notes whenever applicable.

Examples include:

- Mixed timestamp formats
- Missing timestamps
- Invalid timestamps
- Contradictory authentication results
- Conflicting security alerts
- Repeated events
- Conflicting analyst conclusions
- Missing host information
- Missing source information
- Conflicting IP reputation
- Narrative claims mixed with telemetry
- Insufficient context
- Malformed records

============================================================
19. OVERALL RISK
============================================================

Overall risk must reflect both evidence and uncertainty.

Do not simply use the highest individual finding severity.

Consider:

- strength of evidence
- corroboration
- contradictions
- uncertainty
- potential impact
- whether compromise is actually demonstrated

============================================================
20. EXECUTIVE SUMMARY
============================================================

The executive summary must:

- identify the input classification,
- summarize important security observations,
- acknowledge major uncertainty,
- avoid declaring compromise unless supported,
- distinguish alerts from verified telemetry.

============================================================
21. INVESTIGATION PRIORITY
============================================================

Investigation priorities must be supported by the input.

Examples of appropriate priorities include:

- validating privileged authentication,
- investigating suspicious process execution,
- correlating outbound connections,
- validating malware detections,
- reviewing firewall state changes,
- investigating sensitive-file access,
- validating possible lateral movement.

Do not create priorities for activity not present in the input.

============================================================
22. TIMELINE
============================================================

Create timeline events only from supported observations.

Each event must contain:

- timestamp
- event
- severity
- evidence

Use the original timestamp where reliable.

Use:

"Unknown"

when the timestamp is missing or unusable.

Do not create a fake chronological sequence from analyst commentary.

============================================================
23. FINDINGS
============================================================

Each finding must contain:

- title
- severity
- confidence
- description
- evidence
- attack_pattern
- recommended_actions

The evidence array must contain concrete observations from the
supplied input.

Do not fabricate evidence.

============================================================
24. OUTPUT FORMAT
============================================================

Return ONLY valid JSON.

Do not use Markdown.

Do not use code fences.

Do not include explanations outside the JSON object.

The JSON must have exactly this top-level structure:

{
  "input_classification": "STRUCTURED|UNSTRUCTURED|MIXED|INSUFFICIENT",
  "data_quality_notes": [
    "string"
  ],
  "overall_risk": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "confidence": "HIGH|MEDIUM|LOW",
  "executive_summary": "string",
  "findings": [
    {
      "title": "string",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "confidence": "HIGH|MEDIUM|LOW",
      "description": "string",
      "evidence": [
        "string"
      ],
      "attack_pattern": "string",
      "recommended_actions": [
        "string"
      ]
    }
  ],
  "timeline": [
    {
      "timestamp": "string",
      "event": "string",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "evidence": "string"
    }
  ],
  "investigation_priority": [
    "string"
  ]
}

============================================================
25. FINAL VALIDATION CHECKLIST
============================================================

Before returning the JSON:

- Verify input_classification.
- Verify data_quality_notes.
- Preserve contradictions.
- Preserve malformed evidence.
- Preserve uncertainty.
- Do not invent timestamps.
- Do not invent IP addresses.
- Do not invent users.
- Do not invent hosts.
- Do not invent commands.
- Do not invent attack relationships.
- Do not treat alerts as proof of compromise.
- Do not treat analyst opinions as telemetry.
- Do not infer successful command execution without evidence.
- Do not infer malware execution from detection alone.
- Do not resolve contradictory reputation results.
- Do not create unsupported attack patterns.
- Every finding must contain concrete evidence.
- Every finding must have valid severity.
- Every finding must have valid confidence.
- Every timeline event must be evidence-grounded.
- Overall risk must reflect uncertainty.
- Executive summary must not overstate the evidence.
- Investigation priorities must be evidence-based.
- Return valid JSON only.
"""


# ---------------------------------------------------------------------------
# Availability
# ---------------------------------------------------------------------------

def ai_available() -> bool:
    """
    Check whether Groq is configured.
    """
    return bool(
        GROQ_API_KEY
        and GROQ_MODEL
    )


# ---------------------------------------------------------------------------
# Groq client
# ---------------------------------------------------------------------------

def _create_client() -> OpenAI:
    """
    Create an OpenAI-compatible client configured for Groq.
    """
    if not GROQ_API_KEY:
        raise RuntimeError(
            "GROQ_API_KEY is not configured."
        )

    if not GROQ_MODEL:
        raise RuntimeError(
            "GROQ_MODEL is not configured."
        )

    return OpenAI(
        api_key=GROQ_API_KEY,
        base_url=GROQ_BASE_URL,
    )


# ---------------------------------------------------------------------------
# User prompt
# ---------------------------------------------------------------------------

def _build_user_prompt(log_text: str) -> str:
    """
    Build the user message containing the raw input.

    The raw input is deliberately passed without preprocessing or
    security interpretation so the model can distinguish structured,
    unstructured, malformed, and mixed evidence.
    """
    return f"""
Analyze the following security input according to the system instructions.

IMPORTANT:

The input may be:

- structured logs
- unstructured text
- mixed logs and narrative
- malformed records
- contradictory records
- incomplete data
- repeated events
- analyst commentary

Do not assume that every line is authoritative telemetry.

Preserve contradictions and explicitly report data-quality problems.

RAW SECURITY INPUT
==================

{log_text}

END RAW SECURITY INPUT
======================

Return ONLY the required JSON object.
"""


# ---------------------------------------------------------------------------
# Error helpers
# ---------------------------------------------------------------------------

def _get_status_code(exc: Exception):
    """
    Extract an HTTP status code from an exception when available.
    """
    return getattr(exc, "status_code", None)


def _get_retry_after_seconds(exc: Exception):
    """
    Extract Retry-After information when available.
    """
    response = getattr(exc, "response", None)

    if response is None:
        return None

    headers = getattr(response, "headers", None)

    if not headers:
        return None

    retry_after = headers.get("retry-after")

    if retry_after is None:
        return None

    try:
        return float(retry_after)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Error classification
# ---------------------------------------------------------------------------

def _is_quota_error(exc: Exception) -> bool:
    """
    Detect Groq quota, billing, or account-limit errors.

    These errors should not be automatically retried.
    """
    status_code = _get_status_code(exc)
    error_text = str(exc).lower()

    quota_markers = (
        "quota",
        "rate limit",
        "billing",
        "insufficient",
        "credits",
        "limit exceeded",
    )

    return (
        status_code == 429
        and any(
            marker in error_text
            for marker in quota_markers
        )
    )


def _is_retryable_error(exc: Exception) -> bool:
    """
    Determine whether a Groq request should be retried.
    """
    if _is_quota_error(exc):
        return False

    status_code = _get_status_code(exc)

    if status_code in {429, 500, 502, 503, 504}:
        return True

    transient_markers = (
        "rate limit",
        "too many requests",
        "temporarily unavailable",
        "service unavailable",
        "overloaded",
        "timeout",
        "timed out",
        "try again later",
        "connection error",
        "server error",
    )

    error_text = str(exc).lower()

    return any(
        marker in error_text
        for marker in transient_markers
    )


# ---------------------------------------------------------------------------
# Provider error formatting
# ---------------------------------------------------------------------------

def _format_provider_error(exc: Exception) -> str:
    """
    Convert a Groq exception into a user-friendly message.
    """
    status_code = _get_status_code(exc)
    error_text = str(exc).strip()

    if _is_quota_error(exc):
        return (
            "Groq API rate or usage limits have been reached. "
            "Please check your Groq API usage and limits."
        )

    if status_code == 429:
        return (
            "Groq rate limit reached. "
            "Please wait a moment and try again."
        )

    if status_code == 503:
        return (
            "Groq is temporarily unavailable. "
            "Please try again in a few minutes."
        )

    if status_code in {500, 502, 504}:
        return (
            "Groq temporarily failed to process the request. "
            "Please try again shortly."
        )

    if error_text:
        return error_text

    return "The Groq provider returned an unknown error."


# ---------------------------------------------------------------------------
# Retry delay
# ---------------------------------------------------------------------------

def _get_retry_delay(
    exc: Exception,
    attempt: int,
) -> float:
    """
    Determine how long to wait before retrying.
    """
    retry_after = _get_retry_after_seconds(exc)

    if retry_after is not None:
        return max(0.0, retry_after)

    index = min(
        attempt - 1,
        len(RETRY_DELAYS_SECONDS) - 1,
    )

    return float(
        RETRY_DELAYS_SECONDS[index]
    )


# ---------------------------------------------------------------------------
# Groq request
# ---------------------------------------------------------------------------

def _request_ai_analysis(
    client: OpenAI,
    log_text: str,
):
    """
    Send the raw security input to Groq with retry handling.
    """
    last_exception = None

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            return client.chat.completions.create(
                model=GROQ_MODEL,
                messages=[
                    {
                        "role": "system",
                        "content": SYSTEM_PROMPT,
                    },
                    {
                        "role": "user",
                        "content": _build_user_prompt(
                            log_text
                        ),
                    },
                ],
                response_format={
                    "type": "json_object",
                },
            )

        except Exception as exc:
            last_exception = exc

            if _is_quota_error(exc):
                raise RuntimeError(
                    f"Groq rate or usage limit reached for "
                    f"model {GROQ_MODEL!r}. "
                    "No automatic retry will be attempted."
                ) from exc

            if not _is_retryable_error(exc):
                raise

            if attempt >= MAX_RETRIES:
                break

            delay = _get_retry_delay(
                exc=exc,
                attempt=attempt,
            )

            print(
                f"Groq request temporarily failed "
                f"(attempt {attempt}/{MAX_RETRIES}). "
                f"Retrying in {delay:.1f} seconds..."
            )

            time.sleep(delay)

    if last_exception is not None:
        provider_message = _format_provider_error(
            last_exception
        )

        raise RuntimeError(
            f"Groq request failed after "
            f"{MAX_RETRIES} attempts. "
            f"{provider_message}"
        ) from last_exception

    raise RuntimeError(
        "Groq request failed without returning a response."
    )


# ---------------------------------------------------------------------------
# Main AI analysis function
# ---------------------------------------------------------------------------

@observe(name="ai-security-log-analysis")
def analyze_logs_with_ai(
    log_text: str,
) -> SecurityAnalysis:
    """
    Analyze security input using Groq.

    The model classifies the input, identifies data-quality problems,
    analyzes supported security evidence, and returns a response
    validated against the SecurityAnalysis Pydantic schema.
    """
    if not log_text or not log_text.strip():
        raise ValueError(
            "No log data was provided."
        )

    if not ai_available():
        missing = []

        if not GROQ_API_KEY:
            missing.append("GROQ_API_KEY")

        if not GROQ_MODEL:
            missing.append("GROQ_MODEL")

        raise RuntimeError(
            "AI security analysis is unavailable. "
            + "; ".join(missing)
        )

    client = _create_client()

    try:
        response = _request_ai_analysis(
            client=client,
            log_text=log_text,
        )

    except Exception as exc:
        raise RuntimeError(
            f"AI security analysis request failed: {exc}"
        ) from exc

    if not response.choices:
        raise RuntimeError(
            "The AI returned no choices."
        )

    message = response.choices[0].message

    if getattr(message, "refusal", None):
        raise RuntimeError(
            f"AI refused the security analysis: "
            f"{message.refusal}"
        )

    content = getattr(
        message,
        "content",
        None,
    )

    if not content or not content.strip():
        raise RuntimeError(
            "The AI returned an empty security analysis."
        )

    try:
        analysis = SecurityAnalysis.model_validate_json(
            content
        )

    except Exception as exc:
        raise RuntimeError(
            "The AI returned JSON that does not match the "
            f"SecurityAnalysis schema: {exc}"
        ) from exc

    # Flush Langfuse telemetry after the analysis is complete.
    try:
        get_client().flush()
    except Exception:
        pass

    return analysis
