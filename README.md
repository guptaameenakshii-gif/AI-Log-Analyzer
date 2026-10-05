# AI Security Warning Log Analyzer

A Gradio-based security log analysis app for reviewing auth, firewall, API, database, and mixed system logs. The tool accepts either a log file upload or pasted log text, sends the data to a Gemini-backed LLM, and renders a structured security assessment with risk scoring, findings, attack-pattern context, timeline events, investigation priorities, and raw JSON output.

This project evolved from a simple parser prototype into an AI-assisted SOC-style analyzer that validates model output against a Pydantic schema and exposes the results in a dashboard UI.

## What the app does

- Accepts uploaded files or manual log input
- Supports .log, .txt, and .csv uploads
- Parses timestamped log lines and preserves non-standard lines as raw evidence
- Sends the log data to Gemini for security interpretation
- Validates the AI response against a strict JSON schema
- Produces:
  - executive summary
  - overall risk level
  - confidence level
  - structured findings
  - timeline of security-relevant events
  - investigation priorities
  - raw JSON output
- Displays the results in a dashboard with severity badges and evidence panels

## Current architecture

The actual application flow is:

1. Log intake from file or manual text
2. Input preparation and validation
3. Gemini LLM request with a security-analysis system prompt
4. Schema validation using Pydantic
5. Gradio dashboard rendering of the structured result

The application is intentionally AI-first and evidence-driven. Security interpretation is performed by the model, while Python enforces request/response structure and handles transient provider failures.

## Tech stack

- Python
- Gradio
- Pydantic
- OpenAI Python client
- Gemini OpenAI-compatible endpoint
- Langfuse
- dotenv
- pytest

## Project layout

```text
app/
  __init__.py
  analyzer.py
  llm.py
  main.py
  schemas.py
  test_llm.py
examples/
  auth_300.log
  mixed_300.log
  security_300.log
tests/
  test_analyzer.py
tools/
  generate_logs.py
README.md
requirements.txt
pytest.ini
```

## Local setup

```bash
python -m venv .venv

# Windows PowerShell
.\.venv\Scripts\Activate.ps1

# macOS/Linux
source .venv/bin/activate

pip install -r requirements.txt
python -m app.main
```

Then open the local Gradio URL shown in the terminal, usually:

```text
http://127.0.0.1:7860
```

## Environment configuration

Create a .env file in the project root with your Gemini settings.

```env
LLM_PROVIDER=gemini
LLM_MODEL=gemini-2.5-flash
GEMINI_API_KEY=your_api_key_here
```

Notes:

- LLM_PROVIDER is defaulted to gemini if omitted.
- LLM_MODEL must be set for the request to run.
- GEMINI_API_KEY is required for AI analysis.
- If the required values are missing, the app reports an AI analysis unavailable error instead of crashing.

## Example log formats

The analyzer expects human-readable logs with timestamps and source context, for example:

```text
2026-09-21 10:15:03 WARN auth-service Failed login attempt user=admin source_ip=10.10.4.21
2026-09-21 10:15:05 WARN auth-service Failed login attempt user=admin source_ip=10.10.4.21
2026-09-21 10:15:07 WARN auth-service Failed login attempt user=admin source_ip=10.10.4.21
```

The application is designed for mixed security telemetry such as:

- authentication failures
- firewall blocks
- privilege-escalation signals
- API failures
- database issues
- suspicious access patterns

## How to use the app

1. Launch the app with python -m app.main.
2. Upload a log file or paste log text into the manual input box.
3. Choose Analyze Logs.
4. Review the dashboard:
   - security overview
   - executive assessment
   - attack timeline
   - findings table
   - investigation details
   - investigation priorities
   - raw JSON
5. Use Clear to reset the interface.

## Generated sample logs

The examples folder contains generated datasets for testing the app:

- examples/security_300.log
- examples/auth_300.log
- examples/mixed_300.log

You can regenerate them with:

```bash
python tools/generate_logs.py
```

## Observability and Langfuse

The project includes Langfuse tracing around the AI analysis workflow. The decorator in [app/llm.py](app/llm.py) wraps the analysis function and automatically flushes the client after a successful response.

This is intended for:

- request-level tracing of AI analysis calls
- monitoring prompt/response behavior
- debugging provider failures and retries
- observing output validation issues

To use it, configure Langfuse in your environment as needed for your deployment. The app does not require Langfuse to run, but when configured it can provide additional observability around the security-analysis pipeline.

## Validation and tests

Run the test suite with:

```bash
pytest -q
```

The tests cover parsing, grouping, event detection, severity behavior, stats, and summary generation.

## Important limitations

- This is a security-analysis support tool, not a SIEM or automated incident-response platform.
- The LLM performs the interpretation from the supplied logs; the app does not treat the logs as authoritative beyond the model request.
- AI output is validated structurally, but human review is still required for final SOC decisions.
- The app does not automatically change systems or remediate incidents.
- Evidence should be treated as log-supported interpretation, not as a guarantee of compromise.

## Summary

The current version is an evidence-oriented, Gemini-backed security log analyzer built around a Gradio dashboard and strongly validated JSON output. It is intended for investigation support, quick triage, and structured review of suspicious log patterns.
