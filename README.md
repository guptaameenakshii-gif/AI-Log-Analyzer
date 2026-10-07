# AI Security Warning Log Analyzer

A Gradio-based AI security log analyzer for reviewing authentication, firewall, API, database, and mixed system logs.

The application combines LLM-based security interpretation with deterministic Python processing and Pydantic validation. It produces structured security findings, evidence-backed timelines, investigation priorities, severity/confidence assessments, and machine-readable JSON output.

The project is designed as an investigation-support tool, not an automated incident-response or SIEM platform.

## Features

1. Upload .log, .txt, and .csv files or paste log text manually
2. Detect and preserve timestamped and non-standard log entries
3. Extract and chronologically order timeline events using deterministic Python logic
4. Analyze security activity using a Groq-hosted LLM
5. Validate AI output with Pydantic
6. Separate severity from confidence
7. Distinguish suspicious activity from confirmed security incidents
8. Preserve original log evidence for investigation
9. Generate structured investigation priorities
10. Recognize private and public IP address ranges
11. Handle malformed, empty, and invalid inputs gracefully
12. Export/report structured results
13. Provide Langfuse observability for AI requests
14. Include automated tests for normal and failure scenarios

## Architecture
The application follows this processing flow:

```text
Log input
  -> Input preparation and validation
  -> Groq security analysis
  -> Pydantic schema validation
  -> Evidence safety checks
  -> Deterministic timeline extraction
  -> AI/Python timeline merge
  -> Investigation priorities
  -> Gradio dashboard and report
```


Responsibilities are intentionally separated:

- **LLM:** interprets security activity and produces structured findings.
- **Pydantic:** validates the structure and allowed values of AI output.
- **Python:** extracts timestamps, preserves evidence, orders timeline events, validates IP classifications, and handles deterministic processing.
- **Langfuse:** provides observability only; it does not determine the security result.

This separation makes the system easier to test and reduces dependence on the LLM for deterministic tasks.

## Security Analysis

- Executive summary
- Overall risk and confidence
- Structured findings with severity, confidence, evidence, and attack-pattern context
- Security activity timeline
- Investigation priorities
- Raw JSON output

### Severity and Confidence

The application keeps severity and confidence separate.

Severity represents how serious the potential security issue could be.

Confidence represents how strongly the available evidence supports the conclusion.

For example:

```text
Severity: HIGH
Confidence: LOW
```


means the potential issue could be serious, but the available evidence is not strong enough to treat it as confirmed.

The analyzer also avoids automatically treating events such as failed logins, MFA failures, or unusual authentication activity as confirmed attacks.

### Evidence Traceability

Findings are designed to remain traceable to the original logs.

Where available, evidence can include:

- Log line number and timestamp
- Event information
- Source IP and user/account
- Original log entry

The goal is to allow an analyst to quickly verify why a finding was generated instead of relying only on the LLM's explanation.

Original log evidence is treated as supporting evidence rather than proof of compromise.

### Deterministic Security Timeline

Timeline generation was deliberately moved away from being completely LLM-dependent.

Python extracts timestamps from the supplied logs and sorts events chronologically. AI-generated timeline context can then be merged with the deterministic timeline.

This means the timeline does not depend on the model correctly ordering timestamps.

- Valid timestamps are normalized where possible.
- Events are sorted chronologically.
- Unknown timestamps are preserved instead of discarded.
- Original log lines remain available as evidence.
- Timeline counts depend on the supplied input; they are not fixed.

### Investigation Priorities

Investigation priorities are generated from the structured findings.

When findings exist, the application produces structured priorities that help an analyst decide what should be investigated first.

When there are genuinely no findings, the application explicitly reports that investigation priorities are not applicable instead of silently returning an empty result.

### IP Address Classification

The analyzer distinguishes private and public IP addresses.

Private RFC1918 ranges are handled explicitly:

- `10.0.0.0/8`
- `172.16.0.0/12`
- `192.168.0.0/16`

Therefore, an address such as 10.10.4.21 is not automatically described as an external IP.

This helps reduce overconfident or technically incorrect security conclusions.

## Technology Stack

Python, Gradio, Pydantic, the OpenAI Python client, Groq's OpenAI-compatible API, Langfuse, `python-dotenv`, pytest, and ReportLab.

## Project Structure
```text
app/
  __init__.py
  analyzer.py
  llm.py
  main.py
  schemas.py
  timeline.py

examples/
  auth_300.log
  mixed_300.log
  security_300.log

tests/
  test_analyzer.py
  test_timeline.py

tools/
  generate_logs.py

README.md
requirements.txt
pytest.ini
```

## Setup

Create and activate a virtual environment:

```powershell
python -m venv .venv

.\.venv312\Scripts\Activate.ps1
```

On macOS/Linux:

```bash
python -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Create a `.env` file in the project root:

```env
GROQ_API_KEY=your_api_key_here
GROQ_MODEL=openai/gpt-oss-120b
```

Start the app:

```bash
python -m app.main
```

Open the local Gradio URL shown in the terminal, usually:

```text
http://127.0.0.1:7860
```

## Using the Application

1. Launch the application with `python -m app.main`.
2. Upload a `.log`, `.txt`, or `.csv` file, or paste log text.
3. Select **Analyze Logs**.
4. Review the security overview, executive assessment, timeline, findings, evidence, priorities, and raw JSON.
5. Select **Clear** to reset the interface.

## Example Input
```text
2026-09-21 10:15:03 WARN auth-service Failed login attempt user=admin source_ip=10.10.4.21
2026-09-21 10:15:05 WARN auth-service Failed login attempt user=admin source_ip=10.10.4.21
2026-09-21 10:15:07 WARN auth-service Failed login attempt user=admin source_ip=10.10.4.21
```

The analyzer can process authentication and MFA failures, firewall blocks, privilege-escalation signals, API failures, database events, and suspicious access patterns.

## Testing and Evaluation

The project includes automated tests covering both normal processing and failure scenarios.

Run the full suite:

```bash
pytest -q
```

Latest verified result: **63 passed**.

### Evaluation Results

| Test case | Expected result | Status |
|---|---|---|
| Structured, messy, and unstructured input | Preserve classification and handle evidence conservatively | Pass |
| Empty input/upload and invalid upload | Return a controlled response | Pass |
| Malformed timestamp | Preserve evidence and flag data quality | Pass |
| Groq unavailable, invalid JSON, or missing fields | Return a controlled provider/schema error | Pass |
| Invalid severity or confidence | Reject unsupported values | Pass |
| Empty findings | Mark priorities as not applicable | Pass |
| Timeline ordering and unknown timestamps | Sort deterministically and preserve events | Pass |
| Evidence traceability and PDF evidence column | Preserve original log evidence | Pass |
| Private/public IP classification | Correctly handle RFC1918 ranges | Pass |
| Langfuse success/error traces | Record request stages and failures | Verified |

The provider-response tests use controlled mocked responses. They demonstrate validation and error-handling behavior but do not claim to measure live LLM classification accuracy.

The test suite currently reports seven identical Langfuse SDK deprecation warnings from asyncio.iscoroutinefunction; these warnings do not cause test failures.

## Langfuse Observability

Langfuse is used to observe the AI analysis workflow rather than to perform the security analysis.

A single analyzer request is represented as one root trace with nested observations:

```text
security-log-analysis
├── prepare-input
├── ai-security-log-analysis
├── evidence-safety
├── build-deterministic-timeline
├── merge-ai-timeline
└── investigation-priorities
```


This structure makes it possible to inspect where time is spent and whether individual processing stages succeed or fail.

- Request latency
- Model/provider and token usage
- Observation status and analysis metadata
- Validation and provider errors

### Live Trace Verification

A live synthetic analysis request was verified in Langfuse on 2026-10-07.

| Measurement | Observed value |
|---|---|
| Trace duration | 6.61 seconds |
| Total tokens | 5,915 |
| Input | 7 lines, 440 characters |
| Timeline events / findings | 7 / 5 |
| Risk / confidence | MEDIUM / MEDIUM |
| Classification | MIXED |
| Provider / model | Groq / `openai/gpt-oss-120b` |


The trace contained the expected nested workflow:

```text
security-log-analysis
├── prepare-input
├── ai-security-log-analysis      6.60s / 5,915 tokens
├── evidence-safety
├── build-deterministic-timeline
├── merge-ai-timeline
└── investigation-priorities
```


The AI generation is the main latency contributor, while the deterministic timeline, merge, evidence-safety, and priority-processing steps complete in milliseconds.

A separate synthetic error trace was also verified where the AI provider was deliberately unavailable. The trace recorded the error without producing an unhandled application exception.

- Latency and token usage
- Model/provider information
- Validation and provider failures
- Per-stage processing behavior

Langfuse is not part of the security decision-making logic.

## Sensitive Log Data

Security logs can contain sensitive information including usernames, IP addresses, hostnames, authentication information, tokens, and internal infrastructure details.

The current application sends supplied log content to Groq for AI analysis. Production logs should therefore only be submitted when the organization's security and data-processing requirements allow it.

- Redact or pseudonymize usernames, hostnames, tokens, credentials, and other sensitive identifiers.
- Keep any re-identification mapping in a separately protected system.
- Sanitize untrusted log content and enforce file-size and input-type limits.
- Store API keys in a secret manager or protected environment; never commit `.env` files or expose secrets in logs.
- Add authentication and authorization before exposing Gradio beyond a trusted local environment.
- Use HTTPS/TLS for externally exposed services.
- Restrict Langfuse access and retention; avoid storing raw logs in observability systems unless required.

The current project does not claim to implement enterprise-grade redaction, access control, or managed secrets. These are production deployment requirements.

## Error Handling

- Input is empty or an uploaded file is invalid
- Logs contain malformed fields
- The Groq API is unavailable
- The AI returns invalid JSON or omits required fields
- Severity or confidence contains an invalid value
- Findings are empty

Instead of exposing an unhandled Python exception to the user, the application returns a controlled error or explicit no-result state.

## Generated Test Logs

The `examples/` directory contains generated datasets:

```text
examples/security_300.log
examples/auth_300.log
examples/mixed_300.log
```

They can be regenerated using:

```bash
python tools/generate_logs.py
```

## Limitations

This project is a security-analysis support tool rather than a complete SOC platform.

- LLM interpretation can be incorrect; human review is required for security decisions.
- The application does not automatically remediate or change systems.
- Suspicious activity is not automatically treated as a confirmed incident.
- Pydantic validation guarantees structure, not factual correctness.
- Preserved evidence supports analyst verification but does not prove compromise by itself.
- Production deployments need additional controls for sensitive logs and credentials.
- Mocked provider tests do not claim deterministic live-model accuracy.

## Design Principles

| Principle | Application |
|---|---|
| Evidence over assumptions | Findings should be supported by the supplied logs. |
| Determinism where possible | Python handles timestamps, ordering, IP classification, and schema validation. |
| Conservative classification | Distinguish suspicious activity, possible attacks, strong evidence, and confirmed incidents. |
| Severity is not confidence | A serious potential issue can still have weak supporting evidence. |
| Human in the loop | The tool supports triage but does not replace analyst judgment. |
| Observability without decision-making | Langfuse does not influence security classification. |