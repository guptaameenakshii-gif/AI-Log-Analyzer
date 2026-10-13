# AI Security Warning Log Analyzer

A Python-based security log triage application that combines LLM-powered analysis with deterministic processing to turn authentication, firewall, API, database, and mixed system logs into structured, evidence-backed security findings.

The application uses a Groq-hosted language model for security interpretation, Python for deterministic processing, Pydantic for schema validation, Gradio for the user interface, and Langfuse for LLM observability.

This project is designed as an investigation-support prototype. It helps analysts organize and prioritize suspicious activity but does not independently confirm a compromise, replace a SIEM, or perform automated incident response.

## Highlights

* **Evidence traceability:** Preserves relevant log context and source line numbers while redacting usernames in report evidence.
* **Deterministic timelines:** Extracts timestamps and orders events using Python.
* **Structured security assessment:** Separates severity from confidence and organizes investigation priorities.
* **Validated model output:** Uses Pydantic to validate the structure and allowed values of AI responses.
* **Conservative classification:** Avoids treating suspicious activity as a confirmed security incident without sufficient evidence.
* **IP address classification:** Recognizes private IPv4 ranges and distinguishes them from public addresses.
* **Report generation:** Presents findings through a Gradio interface and supports structured output.
* **LLM observability:** Integrates Langfuse to inspect processing stages, latency, token usage, and errors.
* **Automated tests:** Covers normal processing, malformed inputs, validation failures, and provider-error scenarios.

## Features

1. Upload `.log`, `.txt`, and `.csv` files or paste log text manually.
2. Process timestamped and non-standard log entries.
3. Extract and chronologically order timeline events using deterministic Python logic.
4. Analyze security activity using a Groq-hosted LLM.
5. Validate AI output with Pydantic.
6. Assess severity and confidence separately.
7. Distinguish suspicious activity from confirmed security incidents.
8. Preserve original log evidence for investigation.
9. Generate structured investigation priorities.
10. Classify private and public IP addresses.
11. Handle empty, malformed, and invalid inputs with controlled responses.
12. Present structured investigation results and support report output.
13. Provide Langfuse observability for AI requests.
14. Include automated tests for normal and failure scenarios.

## Demo

The analyzer accepts security logs and produces structured findings intended to support investigation and triage.

### Example input

```text
2026-09-21 10:15:03 WARN auth-service Failed login attempt user=admin source_ip=10.10.4.21
2026-09-21 10:15:05 WARN auth-service Failed login attempt user=admin source_ip=10.10.4.21
2026-09-21 10:15:07 WARN auth-service Failed login attempt user=admin source_ip=10.10.4.21
```

This example is illustrative. Repeated authentication failures may warrant investigation, but they do not by themselves prove an account compromise.

### What to investigate

Depending on the supplied logs and the model's analysis, the application can help surface:

* Repeated authentication failures and unusual access patterns
* Relevant timestamps and supporting log evidence
* Severity and confidence assessments
* Chronological event timelines
* Suggested investigation priorities
* Structured findings and machine-readable output

The actual findings depend on the input, deterministic processing, and model response.

### Application screenshot

Add a screenshot of the running Gradio application here after capturing one with synthetic log data.

Suggested repository location: `screenshots/demo.png`

Once the screenshot is saved, you can embed it using:

```markdown
![AI Security Warning Log Analyzer demo](screenshots/demo.png)
```

## Architecture

The application follows this processing flow:

```text
Log input
   |
   v
Input preparation and validation
   |
   v
Groq security analysis
   |
   v
Pydantic schema validation
   |
   v
Evidence safety checks
   |
   v
Deterministic timeline extraction
   |
   v
AI/Python timeline merge
   |
   v
Investigation priorities
   |
   v
Gradio dashboard and report
```

### Component responsibilities

* **LLM:** Interprets security activity and produces structured findings.
* **Pydantic:** Validates the structure and allowed values of model output.
* **Python:** Extracts timestamps, preserves evidence, orders timeline events, classifies IP addresses, and handles deterministic processing.
* **Gradio:** Provides the user interface for submitting logs and reviewing results.
* **Langfuse:** Provides observability for the AI workflow without determining the security result.

This separation makes the application easier to test and reduces dependence on the language model for tasks that can be performed deterministically.

## Security Analysis

The application can present the following types of results, depending on the input and analysis:

* Executive summary
* Overall risk and confidence assessments
* Structured findings with severity, confidence, evidence, and attack-pattern context
* Security activity timeline
* Investigation priorities
* Raw JSON output

### Severity and confidence

The application keeps severity and confidence separate.

**Severity** represents how serious the potential security issue could be.

**Confidence** represents how strongly the available evidence supports the conclusion.

For example:

```text
Severity: HIGH
Confidence: LOW
```

This means the potential issue could be serious, but the available evidence is not strong enough to treat the conclusion as confirmed.

Failed logins, MFA failures, and unusual authentication activity are not automatically equivalent to confirmed attacks.

### Evidence traceability

Findings are designed to remain traceable to the supplied logs.

Where available, evidence can include:

* Log line number and timestamp
* Event information
* Source IP and user or account
* Original log entry

The goal is to help analysts verify why a finding was generated instead of relying only on an AI-generated explanation.

Original log evidence supports investigation but does not, by itself, prove a compromise.

### Deterministic security timeline

Timeline generation is not entirely dependent on the LLM.

Python extracts timestamps from supplied logs and sorts events chronologically. AI-generated timeline context can then be merged with the deterministic timeline.

The implementation is designed to:

* Normalize valid timestamps where possible
* Sort events chronologically
* Preserve entries with unknown timestamps instead of silently discarding them
* Keep original log lines available as evidence
* Derive timeline counts from the supplied input rather than assuming fixed counts

### Investigation priorities

Investigation priorities are generated from structured findings.

When findings exist, the application produces priorities intended to help analysts decide what to investigate first.

When there are no findings, the application explicitly reports that investigation priorities are not applicable instead of silently returning an empty result.

### IP address classification

The analyzer explicitly handles the private IPv4 ranges defined by RFC 1918:

| Private range               | CIDR             |
| --------------------------- | ---------------- |
| 10.0.0.0â€“10.255.255.255     | `10.0.0.0/8`     |
| 172.16.0.0â€“172.31.255.255   | `172.16.0.0/12`  |
| 192.168.0.0â€“192.168.255.255 | `192.168.0.0/16` |

For example, `10.10.4.21` is a private IPv4 address and should not automatically be described as an external public IP.

This classification helps reduce technically incorrect security conclusions. Private/public classification alone does not establish whether an event is malicious.

## Technology Stack

| Technology           | Purpose                                        |
| -------------------- | ---------------------------------------------- |
| Python               | Application logic and deterministic processing |
| Gradio               | User interface                                 |
| Pydantic             | Structured output validation                   |
| OpenAI Python client | Client interface for the model provider        |
| Groq API             | Hosted language-model inference                |
| Langfuse             | LLM observability                              |
| `python-dotenv`      | Environment configuration                      |
| pytest               | Automated testing                              |
| ReportLab            | PDF generation                                 |

## Project Structure

```text
ai_security_warning_log_analyzer/
â”œâ”€â”€ app/
â”‚   â”œâ”€â”€ __init__.py
â”‚   â”œâ”€â”€ analyzer.py
â”‚   â”œâ”€â”€ llm.py
â”‚   â”œâ”€â”€ main.py
â”‚   â”œâ”€â”€ observability.py
â”‚   â”œâ”€â”€ schemas.py
â”‚   â””â”€â”€ timeline.py
â”œâ”€â”€ examples/
â”‚   â”œâ”€â”€ auth_300.log
â”‚   â”œâ”€â”€ mixed_300.log
â”‚   â””â”€â”€ security_300.log
â”œâ”€â”€ tests/
â”‚   â”œâ”€â”€ test_analyzer.py
â”‚   â””â”€â”€ test_timeline.py
â”œâ”€â”€ tools/
â”‚   â””â”€â”€ generate_logs.py
â”œâ”€â”€ README.md
â”œâ”€â”€ requirements.txt
â””â”€â”€ pytest.ini
```

This structure reflects the files described in the project. Verify it against the actual repository before publishing, especially if files have been added, renamed, or removed.

## Setup

### Windows PowerShell

These instructions are for a fresh checkout of the project.

Create and activate a virtual environment:

```powershell
python -m venv .venv312
.\.venv312\Scripts\Activate.ps1
```

Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

If PowerShell prevents script activation, consult your organization's execution-policy guidance rather than weakening system-wide security settings.

### macOS/Linux

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

### Environment configuration

Create a `.env` file in the project root:

```env
GROQ_API_KEY=your_api_key_here
GROQ_MODEL=openai/gpt-oss-120b
LANGFUSE_REDACT_IPS=true
LANGFUSE_REDACT_USERNAMES=true
```
`GROQ_API_KEY` must contain a valid Groq API key for provider-backed AI analysis. `GROQ_MODEL` is optional and defaults to `openai/gpt-oss-120b` when not set. Langfuse credentials and configuration are handled separately by the observability implementation.


Use valid credentials only in your local environment. Do not commit `.env` or publish API keys.

The Langfuse masking settings control configured masking of IP addresses and usernames in observability payloads. Report evidence also redacts usernames independently of these settings. These controls do not guarantee removal of every sensitive value from every field; review the implementation and test redaction before handling production logs.

### Start the application

From the project root, with the virtual environment activated:

```bash
python -m app.main
```

Open the local Gradio URL printed in the terminal. It is commonly:

```text
http://127.0.0.1:7860
```

## Using the Application

1. Launch the application with `python -m app.main`.
2. Upload a `.log`, `.txt`, or `.csv` file, or paste log text.
3. Select **Analyze Logs**.
4. Review the security overview, executive assessment, timeline, findings, evidence, priorities, and raw JSON.
5. Review any generated report supported by the interface.
6. Select **Clear** to reset the interface.

Exact labels and available outputs may vary with the current implementation.

## Testing and Evaluation

The project includes automated tests for normal processing, data-quality issues, AI-provider failures, schema validation, evidence handling, and security guardrails.

Run the full test suite from the project root:

```bash
python -m pytest -q
```

**Latest recorded result: 80 passed in 9.15 seconds.**

This result was observed on October 12, 2026. Rerun the full test suite after changing application code or dependencies before publishing an updated result.

### Evaluation coverage

| Test area                                     | Verified behavior or test objective                                                                             |
| --------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| Structured, mixed, and unstructured input     | Exercise classification and conservative evidence handling                                                      |
| Empty input or invalid upload                 | Check controlled error handling                                                                                 |
| Malformed timestamps                          | Preserve evidence and flag timestamp uncertainty                                                                |
| Provider unavailable or invalid response      | Exercise provider-error handling and response validation                                                        |
| Missing fields or invalid severity/confidence | Reject invalid structured AI output                                                                             |
| Empty findings                                | Handle investigation priorities when no findings exist                                                          |
| Timeline ordering and unknown timestamps      | Test deterministic ordering and timestamp handling                                                              |
| Evidence traceability and PDF evidence column | Check preservation of original log evidence in supported outputs                                                |
| Private/public IP classification              | Test handling of RFC 1918 address ranges                                                                        |
| Langfuse success/error traces                 | Exercise observability for workflow stages and failures                                                         |
| Prompt-injection text in supplied logs        | Test that embedded instructions are treated as untrusted input                                                  |
| Unsupported compromise claims                 | Test that narrative claims are not automatically treated as confirmed incidents                                 |
| Unrelated successful login events             | Test that unrelated telemetry does not automatically validate a compromise claim                                |
| Finding-level compromise guardrail            | Test downgrading unsupported claims across title, severity, confidence, attack pattern, and recommended actions |

Provider-response tests use controlled mocked responses. They demonstrate validation and error-handling behavior; they do not measure live LLM classification accuracy.

Prompt-injection tests verify specific guardrail behavior. They do not establish immunity to every prompt-injection technique. Likewise, compromise-detection tests cover the implemented scenarios and do not prove that every finding is correctly calibrated.

The test suite has previously emitted Langfuse SDK deprecation warnings related to `asyncio.iscoroutinefunction`. Such warnings are not the same as test failures. Confirm the current output before documenting the number or status of warnings.


### Evaluation coverage

| Test area                                     | Intended behavior                                                |
| --------------------------------------------- | ---------------------------------------------------------------- |
| Structured, messy, and unstructured input     | Preserve classification and handle evidence conservatively       |
| Empty input or invalid upload                 | Return a controlled response                                     |
| Malformed timestamps                          | Preserve evidence and handle data-quality issues                 |
| Provider unavailable or invalid response      | Handle provider and schema errors without an unhandled exception |
| Missing fields or invalid severity/confidence | Reject unsupported structured output                             |
| Empty findings                                | Mark priorities as not applicable                                |
| Timeline ordering and unknown timestamps      | Sort deterministically and preserve events                       |
| Evidence traceability and PDF evidence column | Preserve original log evidence in supported outputs              |
| Private/public IP classification              | Correctly handle RFC 1918 ranges                                 |
| Langfuse success/error traces                 | Record workflow stages and failures                              |

Provider-response tests use controlled mocked responses. They demonstrate validation and error-handling behavior; they do not measure live LLM classification accuracy.

The test suite has previously emitted Langfuse SDK deprecation warnings related to `asyncio.iscoroutinefunction`. Such warnings are not the same as test failures. Confirm the current output before documenting the number or status of warnings.

## Langfuse Observability

Langfuse is used to observe the AI analysis workflow rather than perform security classification.

A typical analyzer request is represented as a root trace with nested observations:

security-log-analysis
|-- prepare-input
|-- ai-security-log-analysis
|-- evidence-safety
|-- build-deterministic-timeline
|-- merge-ai-timeline
|-- investigation-priorities

The workflow can help inspect:

* Request latency
* Model/provider and token usage, where reported
* Observation status and analysis metadata
* Validation and provider errors
* Per-stage processing behavior

The AI generation can be the main contributor to request latency. Actual timings depend on the provider, model, network, input size, and response length.

### Verification notes

A synthetic analysis request was previously verified in Langfuse on October 7, 2026. The recorded observations were:

Langfuse provides observability for AI-assisted security log analysis, including tracing analysis stages and recording relevant execution metadata. Provider errors can also be recorded for troubleshooting. Trace details and metadata should be reviewed for sensitive information before being shared.

These are observations from one synthetic request, not benchmark results or expected values for every run.

A separate synthetic error scenario was also previously verified where the AI provider was deliberately unavailable. The trace recorded an error without an unhandled application exception.

Before publishing, verify that the trace evidence is safe to share and remains accessible to intended readers. If access is private or the trace contains any potentially sensitive payloads, remove direct trace URLs from the public README and retain only a sanitized summary.

Langfuse provides observability; it does not independently validate the factual correctness of a security finding.

## Sensitive Log Data

Security logs can contain sensitive information, including usernames, IP addresses, hostnames, authentication information, tokens, and internal infrastructure details.

The application sends supplied log content to Groq for AI analysis. Only submit logs when the applicable security, privacy, and data-processing requirements allow it.

Recommended safeguards include:

* Redact or pseudonymize usernames, hostnames, tokens, credentials, and other sensitive identifiers.
* Keep any re-identification mapping in a separately protected system.
* Validate input types and enforce appropriate file-size and content limits.
* Store API keys in a secret manager or protected environment.
* Never commit `.env` files or expose secrets in logs.
* Add authentication and authorization before exposing Gradio beyond a trusted local environment.
* Use HTTPS/TLS for externally exposed services.
* Restrict Langfuse access and retention.
* Avoid storing raw logs in observability systems unless required and approved.

The current project is a prototype and does not claim to provide enterprise-grade redaction, access control, or managed secrets. These controls should be assessed before production deployment.

## Error Handling

The application includes tests for scenarios such as:

* Empty input or invalid uploads
* Malformed log fields
* An unavailable Groq API
* Invalid JSON or missing required fields in AI output
* Unsupported severity or confidence values
* Empty findings

The intended behavior is to return controlled errors or explicit no-result states rather than expose unhandled Python exceptions to the user.

Test coverage demonstrates the behavior of the tested cases, not the absence of every possible failure.

## Generated Test Logs

The `examples/` directory contains generated datasets:

```text
examples/security_300.log
examples/auth_300.log
examples/mixed_300.log
```

The datasets can be regenerated with:

```bash
python tools/generate_logs.py
```

Confirm that any generated files are synthetic and safe to publish before committing them.

## Limitations

This project is a security-analysis support tool rather than a complete Security Operations Center (SOC) platform.

* LLM interpretation can be incorrect; human review is required for security decisions.
* The application does not automatically remediate or change systems.
* Suspicious activity is not automatically equivalent to a confirmed incident.
* Pydantic validation guarantees structure and allowed values, not factual correctness.
* Preserved evidence supports analyst verification but does not prove compromise by itself.
* Private/public IP classification does not determine whether activity is malicious.
* Production deployments need additional controls for sensitive logs, access, credentials, and data retention.
* Mocked provider tests do not establish deterministic live-model accuracy.
* Results depend on the supplied logs, model behavior, provider availability, and configuration.

## Design Principles

| Principle                             | Application                                                                        |
| ------------------------------------- | ---------------------------------------------------------------------------------- |
| Evidence over assumptions             | Findings should be supported by the supplied logs.                                 |
| Determinism where possible            | Python handles timestamps, ordering, IP classification, and structured validation. |
| Conservative classification           | Distinguish suspicious activity from confirmed incidents.                          |
| Severity is not confidence            | A potentially serious issue can still have weak supporting evidence.               |
| Human in the loop                     | The tool supports triage but does not replace analyst judgment.                    |
| Observability without decision-making | Langfuse monitors the workflow rather than determining the security result.        |

## Future Improvements

Potential next steps include:

* Add a verified screenshot and a sanitized end-to-end example.
* Expand test coverage for additional log formats and edge cases.
* Improve configuration validation and user-facing diagnostics.
* Document the exact masking guarantees and test them across all observability payloads.
* Add authentication, authorization, and deployment hardening before any shared or production deployment.
* Evaluate live-model output quality using a documented, reproducible dataset and human-reviewed criteria.

## License

Add a license section if you intend to distribute the project publicly. Choose a license that matches how you want others to use, modify, and redistribute the code.