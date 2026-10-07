import html
import json
import tempfile
from datetime import datetime
from pathlib import Path
from uuid import uuid4

import gradio as gr

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import (
    ParagraphStyle,
    getSampleStyleSheet,
)
from reportlab.lib.units import mm
from reportlab.platypus import (
    LongTable,
    Paragraph,
    PageBreak,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from .analyzer import analyze_log


# ============================================================
# HELPERS
# ============================================================

def safe(value) -> str:
    """HTML-escape values before inserting into generated HTML."""
    return html.escape("" if value is None else str(value))


def normalize_file(file_value):
    """Return a usable file path from Gradio file input."""

    if not file_value:
        return None

    if isinstance(file_value, str):
        return file_value

    if isinstance(file_value, dict):
        return (
            file_value.get("path")
            or file_value.get("name")
            or file_value.get("data")
        )

    path = getattr(file_value, "path", None)

    if path:
        return path

    name = getattr(file_value, "name", None)

    if name:
        return name

    return None


def read_file(file_value) -> str:
    """Read uploaded log file as text."""

    path = normalize_file(file_value)

    if not path:
        return ""

    try:
        return Path(path).read_text(
            encoding="utf-8",
            errors="replace",
        )
    except Exception:
        try:
            return Path(path).read_text(
                errors="replace",
            )
        except Exception:
            return ""


def valid_severity(value) -> str:
    """
    Normalize severity formatting only.

    This does not change the AI's underlying semantics.
    """

    value = str(value or "").upper().strip()

    if value in {
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
        "INFO",
    }:
        return value

    return "MEDIUM"


def valid_confidence(value) -> str:
    """
    Normalize confidence formatting only.

    This does not change the AI's underlying semantics.
    """

    value = str(value or "").upper().strip()

    if value in {
        "HIGH",
        "MEDIUM",
        "LOW",
    }:
        return value

    return "MEDIUM"


def valid_input_classification(value) -> str:
    """
    Normalize the AI input classification.
    """

    value = str(value or "").upper().strip()

    if value in {
        "STRUCTURED",
        "UNSTRUCTURED",
        "MIXED",
        "INSUFFICIENT",
    }:
        return value

    return "INSUFFICIENT"


def severity_class(value) -> str:
    severity = valid_severity(value)

    return {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
        "INFO": "low",
    }.get(
        severity,
        "medium",
    )


def confidence_class(value) -> str:
    confidence = valid_confidence(value)

    return {
        "HIGH": "confidence-high",
        "MEDIUM": "confidence-medium",
        "LOW": "confidence-low",
    }.get(
        confidence,
        "confidence-medium",
    )


def classification_class(value) -> str:
    classification = valid_input_classification(value)

    return {
        "STRUCTURED": "classification-structured",
        "UNSTRUCTURED": "classification-unstructured",
        "MIXED": "classification-mixed",
        "INSUFFICIENT": "classification-insufficient",
    }.get(
        classification,
        "classification-insufficient",
    )


def normalize_list(value):
    """Ensure evidence/actions are rendered as lists."""

    if value is None:
        return []

    if isinstance(value, list):
        return value

    return [value]


# ============================================================
# INPUT QUALITY
# ============================================================

def build_data_quality(result) -> str:
    """
    Render input classification and data-quality limitations.
    """

    if not result or result.get("error"):
        return ""

    classification = valid_input_classification(
        result.get("input_classification")
    )

    notes = normalize_list(
        result.get("data_quality_notes")
    )

    notes = [
        str(note).strip()
        for note in notes
        if str(note).strip()
    ]

    if notes:
        notes_html = "".join(
            f"""
            <div class="quality-item">
                <span class="quality-marker">!</span>
                <span>{safe(note)}</span>
            </div>
            """
            for note in notes
        )
    else:
        notes_html = """
        <div class="detail-muted">
            No significant data-quality limitations were reported.
        </div>
        """

    return f"""
    <div class="panel data-quality-panel">

        <div class="panel-header">

            <div>
                <div class="panel-title">
                    Input Quality & Classification
                </div>

                <div class="panel-description">
                    How the AI interpreted the supplied log data
                </div>
            </div>

            <span class="classification-badge {
                classification_class(classification)
            }">
                {safe(classification)}
            </span>

        </div>

        <div class="quality-body">

            <div class="quality-summary">

                <div class="quality-label">
                    INPUT CLASSIFICATION
                </div>

                <div class="quality-classification">
                    {safe(classification)}
                </div>

            </div>

            <div class="quality-notes">

                <div class="quality-label">
                    DATA QUALITY NOTES
                </div>

                <div class="quality-list">
                    {notes_html}
                </div>

            </div>

        </div>

    </div>
    """


# ============================================================
# DASHBOARD
# ============================================================

def build_dashboard(result) -> str:

    if not result:
        return """
        <div class="dashboard-empty">

            <div class="empty-icon">
                AI
            </div>

            <div>
                <div class="empty-title">
                    Awaiting log analysis
                </div>

                <div class="empty-text">
                    Upload a security log or paste logs manually,
                    then select <strong>Analyze Logs</strong>.
                </div>
            </div>

        </div>
        """

    if result.get("error"):
        return f"""
        <div class="dashboard-empty dashboard-error">

            <div class="empty-icon">
                !
            </div>

            <div>
                <div class="empty-title">
                    Analysis failed
                </div>

                <div class="empty-text">
                    {safe(result.get("error"))}
                </div>
            </div>

        </div>
        """

    findings = result.get("findings") or []
    timeline = result.get("timeline") or []

    valid_findings = [
        finding
        for finding in findings
        if isinstance(finding, dict)
    ]

    critical = sum(
        1
        for finding in valid_findings
        if valid_severity(
            finding.get("severity")
        ) == "CRITICAL"
    )

    high = sum(
        1
        for finding in valid_findings
        if valid_severity(
            finding.get("severity")
        ) == "HIGH"
    )

    priority_count = critical + high

    risk = valid_severity(
        result.get("overall_risk")
    )

    confidence = valid_confidence(
        result.get("confidence")
    )

    classification = valid_input_classification(
        result.get("input_classification")
    )

    source = result.get(
        "source",
        "AI ANALYSIS",
    )

    priority_class = (
        "critical"
        if priority_count
        else "neutral"
    )

    return f"""
    <div class="dashboard">

        <div class="section-heading">

            <div>
                <div class="section-title">
                    Security Overview
                </div>

                <div class="section-subtitle">
                    Current AI security assessment
                </div>
            </div>

        </div>


        <div class="metric-grid">


            <div class="metric-card">

                <div class="metric-label">
                    OVERALL RISK
                </div>

                <div class="metric-value {severity_class(risk)}">
                    {safe(risk)}
                </div>

                <div class="metric-help">
                    AI-assessed security risk
                </div>

            </div>


            <div class="metric-card">

                <div class="metric-label">
                    CONFIDENCE
                </div>

                <div class="metric-value {confidence_class(confidence)}">
                    {safe(confidence)}
                </div>

                <div class="metric-help">
                    Evidence confidence
                </div>

            </div>


            <div class="metric-card">

                <div class="metric-label">
                    INPUT TYPE
                </div>

                <div class="metric-value classification-value">
                    {safe(classification)}
                </div>

                <div class="metric-help">
                    AI input classification
                </div>

            </div>


            <div class="metric-card">

                <div class="metric-label">
                    TIMELINE EVENTS
                </div>

                <div class="metric-value neutral">
                    {len(timeline)}
                </div>

                <div class="metric-help">
                    Security-relevant events
                </div>

            </div>


            <div class="metric-card">

                <div class="metric-label">
                    FINDINGS
                </div>

                <div class="metric-value neutral">
                    {len(valid_findings)}
                </div>

                <div class="metric-help">
                    AI-identified findings
                </div>

            </div>


            <div class="metric-card">

                <div class="metric-label">
                    HIGH / CRITICAL
                </div>

                <div class="metric-value {priority_class}">
                    {priority_count}
                </div>

                <div class="metric-help">
                    Findings requiring priority review
                </div>

            </div>

        </div>


        <div class="source-card">

            <div class="metric-label">
                SOURCE
            </div>

            <div class="source-value">
                {safe(source)}
            </div>

            <div class="metric-help">
                Analysis origin
            </div>

        </div>

    </div>
    """


# ============================================================
# EXECUTIVE ASSESSMENT
# ============================================================

def build_executive_assessment(result) -> str:

    if not result:
        return ""

    if result.get("error"):
        return build_ai_unavailable(
            result.get("error")
        )

    summary = result.get(
        "executive_summary",
        "",
    )

    risk = valid_severity(
        result.get("overall_risk")
    )

    confidence = valid_confidence(
        result.get("confidence")
    )

    if not summary:
        summary = (
            "The AI analyst did not return "
            "an executive summary."
        )

    return f"""
    <div class="panel executive-panel">

        <div class="panel-header">

            <div>

                <div class="panel-title">
                    AI SECURITY ASSESSMENT
                </div>

                <div class="panel-subtitle">
                    Executive Security Assessment
                </div>

                <div class="panel-description">
                    AI-generated interpretation
                    of the supplied evidence
                </div>

            </div>


            <div class="assessment-badges">

                <span class="badge {severity_class(risk)}">
                    {safe(risk)} RISK
                </span>

                <span class="badge {confidence_class(confidence)}">
                    {safe(confidence)} CONFIDENCE
                </span>

            </div>

        </div>


        <div class="executive-summary">
            {safe(summary)}
        </div>

    </div>
    """


# ============================================================
# FINDINGS
# ============================================================

def build_findings_table(findings) -> str:

    findings = [
        finding
        for finding in (findings or [])
        if isinstance(finding, dict)
    ]

    if not findings:
        return """
        <div class="panel">

            <div class="panel-header">

                <div>
                    <div class="panel-title">
                        Security Findings
                    </div>

                    <div class="panel-description">
                        Structured findings returned by
                        the AI security analyst
                    </div>
                </div>

            </div>

            <div class="empty-state compact">

                <div class="empty-text">
                    No structured findings are available.
                </div>

            </div>

        </div>
        """

    rows = []

    for index, finding in enumerate(
        findings,
        start=1,
    ):

        severity = valid_severity(
            finding.get("severity")
        )

        confidence = valid_confidence(
            finding.get("confidence")
        )

        title = finding.get(
            "title",
            "Untitled finding",
        )

        attack_pattern = finding.get(
            "attack_pattern",
            "None identified",
        )

        actions = normalize_list(
            finding.get(
                "recommended_actions"
            )
        )

        action_text = (
            str(actions[0])
            if actions
            else "No recommended action supplied."
        )

        rows.append(
            f"""
            <tr>

                <td class="row-number">
                    {index:02d}
                </td>

                <td>
                    <span class="table-severity {
                        severity_class(severity)
                    }">
                        {safe(severity)}
                    </span>
                </td>

                <td class="finding-title">
                    {safe(title)}
                </td>

                <td>
                    <span class="table-confidence {
                        confidence_class(confidence)
                    }">
                        {safe(confidence)}
                    </span>
                </td>

                <td class="attack-pattern">
                    {safe(attack_pattern)}
                </td>

                <td class="recommended-action">
                    {safe(action_text)}
                </td>

            </tr>
            """
        )

    return f"""
    <div class="panel findings-panel">

        <div class="panel-header">

            <div>

                <div class="panel-title">
                    Security Findings
                </div>

                <div class="panel-description">
                    {len(findings)}
                    findings returned by the
                    AI security analyst
                </div>

            </div>

        </div>


        <div class="table-wrapper">

            <table class="findings-table">

                <thead>

                    <tr>
                        <th>#</th>
                        <th>SEVERITY</th>
                        <th>FINDING</th>
                        <th>CONFIDENCE</th>
                        <th>ATTACK PATTERN</th>
                        <th>RECOMMENDED ACTION</th>
                    </tr>

                </thead>

                <tbody>
                    {''.join(rows)}
                </tbody>

            </table>

        </div>

    </div>
    """


# ============================================================
# TIMELINE
# ============================================================

def build_timeline(timeline) -> str:

    timeline = [
        event
        for event in (timeline or [])
        if isinstance(event, dict)
    ]

    if not timeline:
        return """
        <div class="panel">

            <div class="panel-header">

                <div>
                    <div class="panel-title">
                        Security Activity Timeline
                    </div>

                    <div class="panel-description">
                        AI-selected security-relevant events
                    </div>
                </div>

            </div>

            <div class="empty-state compact">

                <div class="empty-text">
                    No timeline events were returned.
                </div>

            </div>

        </div>
        """

    cards = []

    for index, event in enumerate(
        timeline,
        start=1,
    ):

        timestamp = event.get(
            "timestamp",
            "Unknown",
        )

        severity = valid_severity(
            event.get("severity")
        )

        title = (
            event.get("event")
            or event.get("title")
            or event.get("description")
            or "Security event"
        )

        evidence = (
            event.get("evidence")
            or event.get("raw_log")
            or event.get("log")
            or ""
        )

        cards.append(
            f"""
            <div class="timeline-event">

                <div class="timeline-marker">
                    <span>
                        {index:02d}
                    </span>
                </div>


                <div class="timeline-content">

                    <div class="timeline-topline">

                        <span class="timeline-index">
                            EVENT {index:02d}
                        </span>

                        <span class="timeline-time">
                            {safe(timestamp)}
                        </span>

                        <span class="timeline-severity {
                            severity_class(severity)
                        }">
                            {safe(severity)}
                        </span>

                    </div>


                    <div class="timeline-title">
                        {safe(title)}
                    </div>


                    <div class="timeline-log">
                        {safe(evidence)}
                    </div>

                </div>

            </div>
            """
        )

    return f"""
    <div class="panel timeline-panel">

        <div class="panel-header">

            <div>

                <div class="panel-title">
                    Security Activity Timeline
                </div>

                <div class="panel-description">
                    AI-selected security-relevant events
                </div>

            </div>

            <div class="event-count">
                {len(timeline)} events
            </div>

        </div>


        <div class="timeline">
            {''.join(cards)}
        </div>

    </div>
    """


# ============================================================
# INVESTIGATION DETAILS
# ============================================================

def build_investigation(findings) -> str:

    findings = [
        finding
        for finding in (findings or [])
        if isinstance(finding, dict)
    ]

    if not findings:
        return """
        <div class="panel">

            <div class="panel-header">

                <div>
                    <div class="panel-title">
                        Investigation Details
                    </div>

                    <div class="panel-description">
                        Evidence, interpretation,
                        attack pattern, and actions
                    </div>
                </div>

            </div>

            <div class="empty-state compact">

                <div class="empty-text">
                    No investigation details are available.
                </div>

            </div>

        </div>
        """

    cards = []

    for index, finding in enumerate(
        findings,
        start=1,
    ):

        title = finding.get(
            "title",
            "Untitled finding",
        )

        severity = valid_severity(
            finding.get("severity")
        )

        confidence = valid_confidence(
            finding.get("confidence")
        )

        description = finding.get(
            "description",
            "",
        )

        attack_pattern = finding.get(
            "attack_pattern",
            "None identified",
        )

        evidence = normalize_list(
            finding.get("evidence")
        )

        actions = normalize_list(
            finding.get("recommended_actions")
        )

        evidence_html = "".join(
            f"""
            <div class="evidence-item">
                {safe(item)}
            </div>
            """
            for item in evidence
        )

        actions_html = "".join(
            f"""
            <div class="action-item">

                <span class="action-arrow">
                    →
                </span>

                <span>
                    {safe(item)}
                </span>

            </div>
            """
            for item in actions
        )

        cards.append(
            f"""
            <div class="investigation-card">

                <div class="investigation-number">
                    {index:02d}
                </div>


                <div class="investigation-body">

                    <div class="investigation-title-row">

                        <div class="investigation-title">
                            {safe(title)}
                        </div>

                        <div class="investigation-badges">

                            <span class="badge {
                                severity_class(severity)
                            }">
                                {safe(severity)}
                            </span>

                            <span class="badge {
                                confidence_class(confidence)
                            }">
                                {safe(confidence)}
                            </span>

                        </div>

                    </div>


                    <div class="detail-block">

                        <div class="detail-label">
                            ANALYST INTERPRETATION
                        </div>

                        <div class="detail-text">
                            {safe(description)}
                        </div>

                    </div>


                    <div class="detail-block">

                        <div class="detail-label">
                            ATTACK PATTERN
                        </div>

                        <div class="attack-pattern-large">
                            {safe(attack_pattern)}
                        </div>

                    </div>


                    <div class="detail-block">

                        <div class="detail-label">
                            OBSERVED EVIDENCE
                        </div>

                        <div class="evidence-list">
                            {
                                evidence_html
                                or
                                '<div class="detail-muted">No evidence supplied.</div>'
                            }
                        </div>

                    </div>


                    <div class="detail-block">

                        <div class="detail-label">
                            RECOMMENDED ACTIONS
                        </div>

                        <div class="actions-list">
                            {
                                actions_html
                                or
                                '<div class="detail-muted">No recommended actions supplied.</div>'
                            }
                        </div>

                    </div>

                </div>

            </div>
            """
        )

    return f"""
    <div class="panel investigation-panel">

        <div class="panel-header">

            <div>

                <div class="panel-title">
                    Investigation Details
                </div>

                <div class="panel-description">
                    Evidence, interpretation,
                    attack pattern, and actions
                </div>

            </div>

        </div>


        <div class="investigation-list">
            {''.join(cards)}
        </div>

    </div>
    """


# ============================================================
# INVESTIGATION PRIORITIES
# ============================================================

def build_investigation_priorities(priorities, findings=None) -> str:

    priorities = normalize_list(
        priorities
    )

    if not priorities:
        empty_message = (
            "No investigation priorities are applicable because "
            "no findings were identified."
            if findings is not None and not findings
            else "No investigation priorities were returned."
        )
        return f"""
        <div class="panel">

            <div class="panel-header">

                <div>

                    <div class="panel-title">
                        Investigation Priorities
                    </div>

                    <div class="panel-description">
                        Highest-priority next steps
                        from the AI analyst
                    </div>

                </div>

            </div>

            <div class="empty-state compact">

                <div class="empty-text">
                    {safe(empty_message)}
                </div>

            </div>

        </div>
        """

    items = []

    for index, priority in enumerate(
        priorities,
        start=1,
    ):

        items.append(
            f"""
            <div class="priority-item">

                <div class="priority-number">
                    {index:02d}
                </div>

                <div class="priority-body">

                    <div class="priority-label">
                        INVESTIGATION PRIORITY
                    </div>

                    <div class="priority-text">
                        {safe(priority)}
                    </div>

                </div>

            </div>
            """
        )

    return f"""
    <div class="panel priorities-panel">

        <div class="panel-header">

            <div>

                <div class="panel-title">
                    Investigation Priorities
                </div>

                <div class="panel-description">
                    Highest-priority next steps
                    from the AI analyst
                </div>

            </div>

        </div>


        <div class="priority-list">
            {''.join(items)}
        </div>

    </div>
    """


# ============================================================
# AI UNAVAILABLE
# ============================================================

def build_ai_unavailable(message: str) -> str:

    return f"""
    <div class="panel ai-unavailable">

        <div class="panel-title">
            AI Security Assessment
        </div>

        <div class="empty-state">

            <div class="empty-icon">
                !
            </div>

            <div>

                <div class="empty-title">
                    AI analysis unavailable
                </div>

                <div class="empty-text">
                    {safe(message)}
                </div>

            </div>

        </div>

    </div>
    """


# ============================================================
# PDF REPORT
# ============================================================

def pdf_text(value) -> str:
    """
    Escape text for safe use inside ReportLab Paragraph objects.
    """

    return html.escape(
        "" if value is None else str(value)
    ).replace(
        "\n",
        "<br/>",
    )


def export_security_report(raw_json):

    try:

        if not raw_json or not str(raw_json).strip():
            raise ValueError(
                "No analysis result is available. "
                "Run Analyze Logs first."
            )

        try:
            result = json.loads(raw_json)

        except json.JSONDecodeError as exc:
            raise ValueError(
                f"The current analysis JSON is invalid: {exc}"
            ) from exc

        if not isinstance(result, dict):
            raise ValueError(
                "The analysis result is not a JSON object."
            )

        if result.get("error"):
            raise ValueError(
                f"The analysis itself failed: "
                f"{result['error']}"
            )

        report_path = (
            Path(tempfile.gettempdir())
            / (
                f"security_report_"
                f"{datetime.now():%Y%m%d_%H%M%S}_"
                f"{uuid4().hex[:8]}.pdf"
            )
        )

        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            "ReportTitle",
            parent=styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=20,
            leading=24,
            alignment=TA_CENTER,
            spaceAfter=8,
        )

        subtitle_style = ParagraphStyle(
            "ReportSubtitle",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=10,
            leading=13,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#64748b"),
            spaceAfter=18,
        )

        section_style = ParagraphStyle(
            "ReportSection",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#172033"),
            spaceBefore=12,
            spaceAfter=8,
        )

        body_style = ParagraphStyle(
            "ReportBody",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#475569"),
            spaceAfter=6,
        )

        small_style = ParagraphStyle(
            "ReportSmall",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#475569"),
        )

        raw_json_style = ParagraphStyle(
            "RawJSON",
            parent=styles["Code"],
            fontName="Courier",
            fontSize=6.5,
            leading=8,
            wordWrap="CJK",
        )

        def draw_footer(canvas, doc):

            canvas.saveState()

            canvas.setFont(
                "Helvetica",
                8,
            )

            canvas.setFillColor(
                colors.HexColor("#64748b")
            )

            canvas.drawString(
                doc.leftMargin,
                8 * mm,
                "AI Security Warning Log Analyzer",
            )

            canvas.drawRightString(
                A4[0] - doc.rightMargin,
                8 * mm,
                f"Page {doc.page}",
            )

            canvas.restoreState()

        doc = SimpleDocTemplate(
            str(report_path),
            pagesize=A4,
            rightMargin=14 * mm,
            leftMargin=14 * mm,
            topMargin=14 * mm,
            bottomMargin=14 * mm,
            title="AI Security Analysis Report",
            author="AI Security Warning Log Analyzer",
        )

        story = []

        # ----------------------------------------------------
        # Header
        # ----------------------------------------------------

        story.append(
            Paragraph(
                "AI Security Warning Log Analyzer",
                title_style,
            )
        )

        story.append(
            Paragraph(
                "AI Security Analysis Report",
                subtitle_style,
            )
        )

        story.append(
            Paragraph(
                f"<b>Generated:</b> "
                f"{pdf_text(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}",
                body_style,
            )
        )

        story.append(
            Paragraph(
                f"<b>Source:</b> "
                f"{pdf_text(result.get('source', 'UNKNOWN'))}",
                body_style,
            )
        )

        story.append(
            Paragraph(
                f"<b>Status:</b> "
                f"{pdf_text(result.get('status', 'AI ANALYSIS'))}",
                body_style,
            )
        )

        # ----------------------------------------------------
        # Executive assessment
        # ----------------------------------------------------

        story.append(
            Paragraph(
                "Executive Assessment",
                section_style,
            )
        )

        input_classification = valid_input_classification(
            result.get("input_classification")
        )

        overall_risk = result.get(
            "overall_risk",
            result.get(
                "risk_level",
                "Not specified",
            ),
        )

        confidence = result.get(
            "confidence",
            "Not specified",
        )

        executive_summary = result.get(
            "executive_summary",
            result.get(
                "summary",
                "No executive summary was returned.",
            ),
        )

        assessment_data = [
            [
                Paragraph(
                    "<b>Input Classification</b>",
                    small_style,
                ),
                Paragraph(
                    pdf_text(input_classification),
                    small_style,
                ),
            ],
            [
                Paragraph(
                    "<b>Overall Risk</b>",
                    small_style,
                ),
                Paragraph(
                    pdf_text(overall_risk),
                    small_style,
                ),
            ],
            [
                Paragraph(
                    "<b>Confidence</b>",
                    small_style,
                ),
                Paragraph(
                    pdf_text(confidence),
                    small_style,
                ),
            ],
        ]

        assessment_table = Table(
            assessment_data,
            colWidths=[
                50 * mm,
                132 * mm,
            ],
        )

        assessment_table.setStyle(
            TableStyle(
                [
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.5,
                        colors.HexColor("#d1d5db"),
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "TOP",
                    ),
                    (
                        "BACKGROUND",
                        (0, 0),
                        (0, -1),
                        colors.HexColor("#f8fafc"),
                    ),
                    (
                        "LEFTPADDING",
                        (0, 0),
                        (-1, -1),
                        6,
                    ),
                    (
                        "RIGHTPADDING",
                        (0, 0),
                        (-1, -1),
                        6,
                    ),
                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        6,
                    ),
                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        6,
                    ),
                ]
            )
        )

        story.append(
            assessment_table
        )

        story.append(
            Spacer(1, 8)
        )

        story.append(
            Paragraph(
                pdf_text(executive_summary),
                body_style,
            )
        )

        # ----------------------------------------------------
        # Data quality
        # ----------------------------------------------------

        story.append(
            Paragraph(
                "Input Quality & Classification",
                section_style,
            )
        )

        story.append(
            Paragraph(
                f"<b>Classification:</b> "
                f"{pdf_text(input_classification)}",
                body_style,
            )
        )

        data_quality_notes = (
            result.get("data_quality_notes")
            or []
        )

        if data_quality_notes:

            story.append(
                Paragraph(
                    "<b>Data Quality Notes:</b>",
                    body_style,
                )
            )

            for note in data_quality_notes:

                story.append(
                    Paragraph(
                        f"• {pdf_text(note)}",
                        body_style,
                    )
                )

        else:

            story.append(
                Paragraph(
                    "No significant data-quality limitations "
                    "were reported.",
                    body_style,
                )
            )

        # ----------------------------------------------------
        # Investigation priorities
        # ----------------------------------------------------

        priorities = (
            result.get("investigation_priorities")
            or result.get("investigation_priority")
            or []
        )

        story.append(
            Paragraph(
                "Investigation Priorities",
                section_style,
            )
        )

        if priorities:

            for index, priority in enumerate(
                priorities,
                start=1,
            ):

                story.append(
                    Paragraph(
                        f"<b>{index}.</b> "
                        f"{pdf_text(priority)}",
                        body_style,
                    )
                )

        else:

            story.append(
                Paragraph(
                    "No structured investigation priorities "
                    "were returned.",
                    body_style,
                )
            )

        # ----------------------------------------------------
        # Findings
        # ----------------------------------------------------

        findings = result.get("findings") or []

        story.append(
            Paragraph(
                "Security Findings",
                section_style,
            )
        )

        if findings:

            finding_rows = [
                [
                    Paragraph(
                        "<b>#</b>",
                        small_style,
                    ),
                    Paragraph(
                        "<b>Severity</b>",
                        small_style,
                    ),
                    Paragraph(
                        "<b>Finding</b>",
                        small_style,
                    ),
                    Paragraph(
                        "<b>Confidence</b>",
                        small_style,
                    ),
                    Paragraph(
                        "<b>Attack Pattern</b>",
                        small_style,
                    ),
                    Paragraph(
                        "<b>Recommended Action</b>",
                        small_style,
                    ),
                ]
            ]

            for index, finding in enumerate(
                findings,
                start=1,
            ):

                if not isinstance(
                    finding,
                    dict,
                ):
                    finding = {
                        "title": str(finding)
                    }

                actions = (
                    finding.get("recommended_actions")
                    or finding.get("recommended_action")
                    or ""
                )

                if isinstance(
                    actions,
                    list,
                ):
                    actions = "; ".join(
                        str(item)
                        for item in actions
                    )

                finding_rows.append(
                    [
                        Paragraph(
                            str(index),
                            small_style,
                        ),
                        Paragraph(
                            pdf_text(
                                finding.get(
                                    "severity",
                                    "",
                                )
                            ),
                            small_style,
                        ),
                        Paragraph(
                            pdf_text(
                                finding.get(
                                    "title",
                                    finding.get(
                                        "finding",
                                        "",
                                    ),
                                )
                            ),
                            small_style,
                        ),
                        Paragraph(
                            pdf_text(
                                finding.get(
                                    "confidence",
                                    "",
                                )
                            ),
                            small_style,
                        ),
                        Paragraph(
                            pdf_text(
                                finding.get(
                                    "attack_pattern",
                                    "",
                                )
                            ),
                            small_style,
                        ),
                        Paragraph(
                            pdf_text(actions),
                            small_style,
                        ),
                    ]
                )

            findings_table = LongTable(
                finding_rows,
                colWidths=[
                    8 * mm,
                    20 * mm,
                    40 * mm,
                    22 * mm,
                    35 * mm,
                    57 * mm,
                ],
                repeatRows=1,
            )

            findings_table.setStyle(
                TableStyle(
                    [
                        (
                            "GRID",
                            (0, 0),
                            (-1, -1),
                            0.4,
                            colors.HexColor("#cbd5e1"),
                        ),
                        (
                            "BACKGROUND",
                            (0, 0),
                            (-1, 0),
                            colors.HexColor("#f1f5f9"),
                        ),
                        (
                            "VALIGN",
                            (0, 0),
                            (-1, -1),
                            "TOP",
                        ),
                        (
                            "LEFTPADDING",
                            (0, 0),
                            (-1, -1),
                            4,
                        ),
                        (
                            "RIGHTPADDING",
                            (0, 0),
                            (-1, -1),
                            4,
                        ),
                        (
                            "TOPPADDING",
                            (0, 0),
                            (-1, -1),
                            4,
                        ),
                        (
                            "BOTTOMPADDING",
                            (0, 0),
                            (-1, -1),
                            4,
                        ),
                    ]
                )
            )

            story.append(
                findings_table
            )

        else:

            story.append(
                Paragraph(
                    "No structured security findings "
                    "were returned.",
                    body_style,
                )
            )

        # ----------------------------------------------------
        # Finding details
        # ----------------------------------------------------

        if findings:

            story.append(
                Paragraph(
                    "Finding Details",
                    section_style,
                )
            )

            for index, finding in enumerate(
                findings,
                start=1,
            ):

                if not isinstance(
                    finding,
                    dict,
                ):
                    continue

                title = finding.get(
                    "title",
                    finding.get(
                        "finding",
                        f"Finding {index}",
                    ),
                )

                story.append(
                    Paragraph(
                        f"<b>{index}. "
                        f"{pdf_text(title)}</b>",
                        body_style,
                    )
                )

                for label, key in [
                    ("Severity", "severity"),
                    ("Confidence", "confidence"),
                    ("Description", "description"),
                    ("Attack Pattern", "attack_pattern"),
                    ("Evidence", "evidence"),
                ]:

                    value = finding.get(key)

                    if value is None:
                        continue

                    if isinstance(
                        value,
                        list,
                    ):
                        value = "; ".join(
                            str(item)
                            for item in value
                        )

                    story.append(
                        Paragraph(
                            f"<b>{label}:</b> "
                            f"{pdf_text(value)}",
                            body_style,
                        )
                    )

                actions = (
                    finding.get("recommended_actions")
                    or finding.get("recommended_action")
                )

                if actions:

                    if isinstance(
                        actions,
                        list,
                    ):
                        actions = "; ".join(
                            str(item)
                            for item in actions
                        )

                    story.append(
                        Paragraph(
                            f"<b>Recommended Actions:</b> "
                            f"{pdf_text(actions)}",
                            body_style,
                        )
                    )

                story.append(
                    Spacer(1, 4)
                )

        # ----------------------------------------------------
        # Timeline
        # ----------------------------------------------------

        timeline = result.get("timeline") or []

        story.append(
            Paragraph(
                "Security Activity Timeline",
                section_style,
            )
        )

        if timeline:

            timeline_rows = [
                [
                    Paragraph(
                        "<b>#</b>",
                        small_style,
                    ),
                    Paragraph(
                        "<b>Timestamp</b>",
                        small_style,
                    ),
                    Paragraph(
                        "<b>Severity</b>",
                        small_style,
                    ),
                    Paragraph(
                        "<b>Event</b>",
                        small_style,
                    ),
                    Paragraph(
                        "<b>Evidence</b>",
                        small_style,
                    ),
                ]
            ]

            for index, event in enumerate(
                timeline,
                start=1,
            ):

                if not isinstance(
                    event,
                    dict,
                ):
                    event = {
                        "event": str(event)
                    }

                event_text = (
                    event.get("event")
                    or event.get("title")
                    or event.get("description")
                    or ""
                )

                evidence = (
                    event.get("evidence")
                    or event.get("raw_log")
                    or event.get("log")
                    or ""
                )

                timeline_rows.append(
                    [
                        Paragraph(
                            str(index),
                            small_style,
                        ),
                        Paragraph(
                            pdf_text(
                                event.get(
                                    "timestamp",
                                    "Unknown",
                                )
                            ),
                            small_style,
                        ),
                        Paragraph(
                            pdf_text(
                                event.get(
                                    "severity",
                                    "",
                                )
                            ),
                            small_style,
                        ),
                        Paragraph(
                            pdf_text(event_text),
                            small_style,
                        ),
                        Paragraph(
                            pdf_text(evidence),
                            small_style,
                        ),
                    ]
                )

            timeline_table = LongTable(
                timeline_rows,
                colWidths=[
                    10 * mm,
                    28 * mm,
                    20 * mm,
                    44 * mm,
                    80 * mm,
                ],
                repeatRows=1,
            )

            timeline_table.setStyle(
                TableStyle(
                    [
                        (
                            "GRID",
                            (0, 0),
                            (-1, -1),
                            0.4,
                            colors.HexColor("#cbd5e1"),
                        ),
                        (
                            "BACKGROUND",
                            (0, 0),
                            (-1, 0),
                            colors.HexColor("#f1f5f9"),
                        ),
                        (
                            "VALIGN",
                            (0, 0),
                            (-1, -1),
                            "TOP",
                        ),
                    ]
                )
            )

            story.append(
                timeline_table
            )

        else:

            story.append(
                Paragraph(
                    "No structured timeline events "
                    "were returned.",
                    body_style,
                )
            )

        # ----------------------------------------------------
        # Raw JSON
        # ----------------------------------------------------

        raw_json_text = json.dumps(
            result,
            indent=2,
            default=str,
        )

        story.append(
            PageBreak()
        )

        story.append(
            Paragraph(
                "Raw Analysis JSON",
                section_style,
            )
        )

        story.append(
            Paragraph(
                html.escape(
                    raw_json_text
                ).replace(
                    "\n",
                    "<br/>",
                ),
                raw_json_style,
            )
        )

        doc.build(
            story,
            onFirstPage=draw_footer,
            onLaterPages=draw_footer,
        )

        return str(report_path)

    except Exception as exc:

        import traceback

        traceback.print_exc()

        raise gr.Error(
            f"PDF export failed: {exc}"
        ) from exc


# ============================================================
# HEADER
# ============================================================

HEADER_HTML = """
<div class="app-header">

    <div class="brand-mark">
        S
    </div>

    <div class="brand-copy">

        <div class="brand-title">
            AI Security Warning Log Analyzer
        </div>

        <div class="brand-subtitle">
            AI-driven evidence analysis
        </div>

    </div>

    <div class="ai-status">

        <span class="status-dot"></span>

        <div>

            <div class="status-title">
                AI ANALYST READY
            </div>

            <div class="status-subtitle">
                Groq security analysis engine
            </div>

        </div>

    </div>

</div>
"""


# ============================================================
# MAIN ANALYSIS
# ============================================================

def analyze_logs(
    file_input,
    manual_logs,
):
    """
    Analyze uploaded or manually supplied logs.

    Returns exactly 8 values because the Gradio event
    declares exactly 8 analysis outputs.
    """

    uploaded_text = read_file(
        file_input
    )

    manual_text = (
        manual_logs or ""
    ).strip()

    # File input takes priority.
    log_text = (
        uploaded_text.strip()
        if uploaded_text.strip()
        else manual_text
    )

    if not log_text:

        empty_result = {
            "error": "No log input supplied.",
        }

        return (
            build_dashboard(
                empty_result
            ),
            "",
            "",
            build_timeline([]),
            build_findings_table([]),
            build_investigation([]),
            build_investigation_priorities([]),
            json.dumps(
                empty_result,
                indent=2,
            ),
        )

    source = (
        "FILE"
        if uploaded_text.strip()
        else "MANUAL"
    )

    try:

        result = analyze_log(
            log_text
        )

        if result is None:
            raise ValueError(
                "The AI analyzer returned no result."
            )

        result = dict(result)

        result["source"] = source
        result["status"] = "AI ANALYSIS"

        findings = (
            result.get("findings")
            or []
        )

        timeline = (
            result.get("timeline")
            or []
        )

        priorities = (
            result.get(
                "investigation_priorities"
            )
            or result.get(
                "investigation_priority"
            )
            or []
        )

        return (
            build_dashboard(result),
            build_data_quality(result),
            build_executive_assessment(result),
            build_timeline(timeline),
            build_findings_table(findings),
            build_investigation(findings),
            build_investigation_priorities(
                priorities,
                findings=findings,
            ),
            json.dumps(
                result,
                indent=2,
                default=str,
            ),
        )

    except Exception as exc:

        error_message = str(exc)

        error_result = {
            "error": error_message,
            "source": source,
            "status": "ANALYSIS FAILED",
        }

        return (
            build_dashboard(
                error_result
            ),
            "",
            build_ai_unavailable(
                error_message
            ),
            build_timeline([]),
            build_findings_table([]),
            build_investigation([]),
            build_investigation_priorities([]),
            json.dumps(
                error_result,
                indent=2,
            ),
        )


# ============================================================
# FILE PREVIEW
# ============================================================

def load_file_preview(file_input):

    text = read_file(
        file_input
    )

    if not text:
        return ""

    return text


# ============================================================
# CLEAR
# ============================================================

def clear_all():

    return (
        None,
        "",
        "",
        build_dashboard(None),
        "",
        "",
        build_timeline([]),
        build_findings_table([]),
        build_investigation([]),
        build_investigation_priorities([]),
        "{}",
        None,
    )


# ============================================================
# CSS
# ============================================================

CSS = r"""
:root {
    --bg: #f4f6f9;
    --surface: #ffffff;
    --surface-2: #f8fafc;

    --text: #172033;
    --text-2: #475569;
    --text-3: #64748b;

    --border: #d9e1ea;

    --critical: #b42318;
    --critical-bg: #fee4e2;

    --high: #b54708;
    --high-bg: #ffead5;

    --medium: #a15c00;
    --medium-bg: #fff1c7;

    --low: #176b42;
    --low-bg: #dcfce7;

    --blue: #2563eb;
    --blue-bg: #eff6ff;
}


html,
body,
.gradio-container {
    background: var(--bg) !important;
    color: var(--text) !important;
}


.gradio-container {
    max-width: 1500px !important;
    margin: 0 auto !important;

    --body-text-color: var(--text) !important;
    --body-text-color-subdued: var(--text-3) !important;
    --block-label-text-color: var(--text-2) !important;
    --block-title-text-color: var(--text) !important;
    --input-text-color: var(--text) !important;
}


.gradio-container input,
.gradio-container textarea,
.gradio-container select,
.gradio-container [contenteditable="true"] {
    color: #172033 !important;
    -webkit-text-fill-color: #172033 !important;
    background: #ffffff !important;
    border-color: var(--border) !important;
    caret-color: #172033 !important;
}


.gradio-container input::placeholder,
.gradio-container textarea::placeholder {
    color: #64748b !important;
    -webkit-text-fill-color: #64748b !important;
    opacity: 1 !important;
}


.gradio-container button {
    color: var(--text-2) !important;
    -webkit-text-fill-color: var(--text-2) !important;
}


.analyze-button,
.analyze-button * {
    color: #ffffff !important;
    -webkit-text-fill-color: #ffffff !important;
}


.analyze-button {
    min-height: 46px !important;
    border-radius: 10px !important;
    background: #172033 !important;
    border: 1px solid #172033 !important;
    font-weight: 800 !important;
}


.clear-button,
.export-button {
    min-height: 46px !important;
    border-radius: 10px !important;
    background: #ffffff !important;
    border: 1px solid var(--border) !important;
}


.app-header {
    display: flex;
    align-items: center;
    gap: 16px;
    padding: 22px 24px;
    margin-bottom: 20px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 16px;
    box-shadow: 0 2px 10px rgba(15, 23, 42, 0.04);
}


.brand-mark {
    width: 44px;
    height: 44px;

    display: flex;
    align-items: center;
    justify-content: center;

    border-radius: 12px;

    background: #172033;
    color: #ffffff !important;

    font-size: 20px;
    font-weight: 800;
}


.brand-copy {
    flex: 1;
}


.brand-title {
    color: var(--text) !important;
    font-size: 23px;
    line-height: 1.2;
    font-weight: 800;
}


.brand-subtitle {
    margin-top: 5px;
    color: var(--text-3) !important;
    font-size: 13px;
}


.ai-status {
    display: flex;
    align-items: center;
    gap: 9px;

    padding: 9px 13px;

    border-radius: 10px;

    background: #ecfdf3;
    border: 1px solid #b7ebc6;
}


.status-dot {
    width: 9px;
    height: 9px;
    border-radius: 50%;
    background: #16a34a;
}


.status-title {
    color: #166534 !important;
    font-size: 11px;
    font-weight: 800;
    letter-spacing: 0.05em;
}


.status-subtitle {
    margin-top: 2px;
    color: #4b6354 !important;
    font-size: 11px;
}


.input-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 18px;
}


.input-title {
    color: var(--text) !important;
    font-size: 16px;
    font-weight: 800;
}


.input-description {
    margin-top: 4px;
    color: var(--text-3) !important;
    font-size: 12px;
}


.panel {
    margin-bottom: 18px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 14px;
    overflow: hidden;
}


.panel-header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 16px;
    padding: 18px 20px;
    border-bottom: 1px solid var(--border);
}


.panel-title {
    color: var(--text) !important;
    font-size: 15px;
    font-weight: 800;
}


.panel-subtitle {
    margin-top: 3px;
    color: var(--text) !important;
    font-size: 18px;
    font-weight: 800;
}


.panel-description {
    margin-top: 4px;
    color: var(--text-3) !important;
    font-size: 12px;
}


.section-heading {
    margin-bottom: 12px;
}


.section-title {
    color: var(--text) !important;
    font-size: 17px;
    font-weight: 800;
}


.section-subtitle {
    margin-top: 3px;
    color: var(--text-3) !important;
    font-size: 12px;
}


.dashboard {
    margin-bottom: 18px;
}


.metric-grid {
    display: grid;
    grid-template-columns: repeat(6, minmax(0, 1fr));
    gap: 10px;
}


.metric-card,
.source-card {
    min-height: 112px;
    padding: 16px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
}


.source-card {
    margin-top: 10px;
    min-height: auto;
}


.metric-label {
    color: var(--text-3) !important;
    font-size: 10px;
    font-weight: 800;
    letter-spacing: 0.04em;
}


.metric-value {
    margin-top: 9px;
    color: var(--text) !important;
    font-size: 25px;
    line-height: 1;
    font-weight: 900;
}


.metric-value.critical {
    color: var(--critical) !important;
}


.metric-value.high {
    color: var(--high) !important;
}


.metric-value.medium {
    color: var(--medium) !important;
}


.metric-value.low {
    color: var(--low) !important;
}


.metric-value.neutral {
    color: var(--text) !important;
}


.classification-value {
    font-size: 13px !important;
    line-height: 1.25 !important;
}


.source-value {
    margin-top: 7px;
    color: var(--text) !important;
    font-size: 15px;
    font-weight: 900;
}


.metric-help {
    margin-top: 8px;
    color: var(--text-3) !important;
    font-size: 11px;
}


.badge,
.table-severity,
.table-confidence,
.timeline-severity,
.classification-badge {
    display: inline-flex;
    align-items: center;
    padding: 4px 8px;
    border-radius: 999px;
    font-size: 10px;
    font-weight: 800;
    letter-spacing: 0.03em;
}


.critical {
    color: var(--critical) !important;
    background: var(--critical-bg);
}


.high {
    color: var(--high) !important;
    background: var(--high-bg);
}


.medium {
    color: var(--medium) !important;
    background: var(--medium-bg);
}


.low {
    color: var(--low) !important;
    background: var(--low-bg);
}


.confidence-high {
    color: #1d4ed8 !important;
    background: #dbeafe;
}


.confidence-medium {
    color: #92400e !important;
    background: #fef3c7;
}


.confidence-low {
    color: #64748b !important;
    background: #f1f5f9;
}


.classification-structured {
    color: #166534 !important;
    background: #dcfce7;
}


.classification-unstructured {
    color: #92400e !important;
    background: #fef3c7;
}


.classification-mixed {
    color: #1d4ed8 !important;
    background: #dbeafe;
}


.classification-insufficient {
    color: #64748b !important;
    background: #f1f5f9;
}


.assessment-badges,
.investigation-badges {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
}


.executive-summary {
    padding: 20px;
    color: var(--text-2) !important;
    font-size: 14px;
    line-height: 1.75;
    overflow-wrap: anywhere;
}


.quality-body {
    display: grid;
    grid-template-columns: 220px minmax(0, 1fr);
    gap: 24px;
    padding: 18px 20px;
}


.quality-label {
    margin-bottom: 7px;
    color: var(--text-3) !important;
    font-size: 10px;
    font-weight: 800;
    letter-spacing: 0.05em;
}


.quality-classification {
    color: var(--text) !important;
    font-size: 18px;
    font-weight: 900;
}


.quality-list {
    display: flex;
    flex-direction: column;
    gap: 7px;
}


.quality-item {
    display: flex;
    align-items: flex-start;
    gap: 9px;

    padding: 8px 10px;

    background: #f8fafc;

    border: 1px solid #e7ecf2;

    border-radius: 7px;

    color: var(--text-2) !important;

    font-size: 12px;
    line-height: 1.55;
}


.quality-marker {
    display: inline-flex;
    align-items: center;
    justify-content: center;

    width: 18px;
    min-width: 18px;
    height: 18px;

    border-radius: 50%;

    background: #fef3c7;
    color: #92400e !important;

    font-size: 10px;
    font-weight: 900;
}


.table-wrapper {
    width: 100%;
    overflow-x: auto;
    background: #ffffff;
}


.findings-table {
    width: 100%;
    border-collapse: collapse;

    color: var(--text) !important;

    font-size: 12px;

    background: #ffffff !important;
}


.findings-table th {
    padding: 11px 12px;

    text-align: left;

    color: var(--text-3) !important;

    background: var(--surface-2) !important;

    border-bottom: 1px solid var(--border);

    font-size: 10px;
    font-weight: 800;
}


.findings-table td {
    padding: 14px 12px;

    color: var(--text-2) !important;

    background: #ffffff !important;

    border-bottom: 1px solid #edf1f5;

    vertical-align: top;
}


.findings-table .finding-title,
.findings-table .attack-pattern {
    color: var(--text) !important;
    font-weight: 700;
}


.findings-table .attack-pattern {
    min-width: 180px;
}


.findings-table .recommended-action {
    min-width: 220px;
    line-height: 1.5;
}


.timeline {
    padding: 8px 20px 20px;
}


.timeline-event {
    display: flex;
    gap: 14px;
    padding: 13px 0;
    border-bottom: 1px solid #edf1f5;
}


.timeline-event:last-child {
    border-bottom: none;
}


.timeline-marker {
    width: 34px;
    min-width: 34px;

    display: flex;
    justify-content: center;

    padding-top: 2px;
}


.timeline-marker span {
    display: flex;
    align-items: center;
    justify-content: center;

    width: 30px;
    height: 30px;

    border-radius: 8px;

    background: #eef2f7;

    color: var(--text) !important;

    font-size: 10px;
    font-weight: 800;
}


.timeline-content {
    flex: 1;
    min-width: 0;
}


.timeline-topline {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 7px;
}


.timeline-index {
    color: var(--text-3) !important;
    font-size: 10px;
    font-weight: 800;
}


.timeline-time {
    color: var(--text-2) !important;

    font-family:
        ui-monospace,
        SFMono-Regular,
        Menlo,
        monospace;

    font-size: 11px;
}


.timeline-title {
    margin-top: 6px;

    color: var(--text) !important;

    font-size: 13px;
    font-weight: 750;

    overflow-wrap: anywhere;
}


.timeline-log {
    margin-top: 5px;

    padding: 8px 10px;

    background: #f8fafc;

    border: 1px solid #e7ecf2;

    border-radius: 7px;

    color: #475569 !important;

    font-family:
        ui-monospace,
        SFMono-Regular,
        Menlo,
        monospace;

    font-size: 10px;

    line-height: 1.5;

    overflow-wrap: anywhere;
}


.event-count {
    color: var(--text-3) !important;
    font-size: 11px;
    font-weight: 700;
}


.investigation-list {
    padding: 4px 20px 20px;
}


.investigation-card {
    display: flex;
    gap: 15px;

    padding: 18px 0;

    border-bottom: 1px solid #edf1f5;
}


.investigation-card:last-child {
    border-bottom: none;
}


.investigation-number,
.priority-number {
    width: 38px;
    min-width: 38px;
    height: 38px;

    display: flex;
    align-items: center;
    justify-content: center;

    border-radius: 10px;

    background: #172033;

    color: #ffffff !important;

    font-size: 11px;
    font-weight: 800;
}


.investigation-body {
    flex: 1;
    min-width: 0;
}


.investigation-title-row {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 14px;
}


.investigation-title {
    color: var(--text) !important;

    font-size: 16px;
    font-weight: 800;

    overflow-wrap: anywhere;
}


.detail-block {
    margin-top: 16px;
}


.detail-label {
    margin-bottom: 7px;

    color: var(--text-3) !important;

    font-size: 10px;
    font-weight: 800;

    letter-spacing: 0.04em;
}


.detail-text {
    color: var(--text-2) !important;

    font-size: 13px;
    line-height: 1.65;

    overflow-wrap: anywhere;
}


.attack-pattern-large {
    display: inline-block;

    max-width: 100%;

    padding: 6px 10px;

    border-radius: 7px;

    background: var(--blue-bg);

    border: 1px solid #dbeafe;

    color: #1d4ed8 !important;

    font-size: 12px;
    font-weight: 800;

    overflow-wrap: anywhere;
}


.evidence-list,
.actions-list,
.quality-list {
    display: flex;
    flex-direction: column;
    gap: 6px;
}


.evidence-item {
    padding: 8px 10px;

    border-left: 3px solid #cbd5e1;

    background: #f8fafc;

    color: #475569 !important;

    font-family:
        ui-monospace,
        SFMono-Regular,
        Menlo,
        monospace;

    font-size: 10px;

    line-height: 1.55;

    overflow-wrap: anywhere;
}


.action-item {
    display: flex;
    gap: 8px;

    color: var(--text-2) !important;

    font-size: 12px;
    line-height: 1.6;

    overflow-wrap: anywhere;
}


.action-arrow {
    color: var(--blue) !important;
    font-weight: 900;
}


.detail-muted {
    color: var(--text-3) !important;
    font-size: 12px;
}


.priority-list {
    padding: 4px 20px 20px;
}


.priority-item {
    display: flex;
    gap: 14px;

    padding: 15px 0;

    border-bottom: 1px solid #edf1f5;
}


.priority-item:last-child {
    border-bottom: none;
}


.priority-number {
    width: 34px;
    min-width: 34px;
    height: 34px;

    border-radius: 9px;

    font-size: 10px;
}


.priority-body {
    flex: 1;
    min-width: 0;
}


.priority-label {
    color: var(--text-3) !important;

    font-size: 9px;
    font-weight: 800;

    letter-spacing: 0.05em;
}


.priority-text {
    margin-top: 4px;

    color: var(--text) !important;

    font-size: 13px;
    line-height: 1.55;

    font-weight: 650;

    overflow-wrap: anywhere;
}


.dashboard-empty,
.empty-state {
    display: flex;
    align-items: center;
    gap: 14px;

    padding: 22px;

    background: var(--surface);

    border: 1px solid var(--border);

    border-radius: 14px;
}


.empty-state.compact {
    border: none;
    border-radius: 0;
}


.empty-icon {
    width: 38px;
    height: 38px;

    display: flex;
    align-items: center;
    justify-content: center;

    flex-shrink: 0;

    border-radius: 10px;

    background: #eef2f7;

    color: var(--text) !important;

    font-size: 12px;
    font-weight: 900;
}


.empty-title {
    color: var(--text) !important;
    font-weight: 800;
}


.empty-text {
    margin-top: 4px;

    color: var(--text-3) !important;

    font-size: 12px;
    line-height: 1.5;

    overflow-wrap: anywhere;
}


.dashboard-error .empty-icon {
    background: var(--critical-bg);
    color: var(--critical) !important;
}


.raw-json textarea,
.raw-json textarea:focus {
    background: #111827 !important;

    color: #dbe5f0 !important;

    -webkit-text-fill-color: #dbe5f0 !important;

    border-color: #263244 !important;

    font-family:
        ui-monospace,
        SFMono-Regular,
        Menlo,
        Monaco,
        Consolas,
        monospace !important;

    font-size: 11px !important;
    line-height: 1.55 !important;
}


.raw-json-heading {
    margin-top: 10px;
    margin-bottom: 10px;
}


@media (max-width: 1100px) {

    .metric-grid {
        grid-template-columns:
            repeat(3, minmax(0, 1fr));
    }

}


@media (max-width: 760px) {

    .app-header {
        align-items: flex-start;
        flex-wrap: wrap;
    }


    .ai-status {
        width: 100%;
    }


    .metric-grid {
        grid-template-columns:
            repeat(2, minmax(0, 1fr));
    }


    .investigation-title-row {
        flex-direction: column;
    }


    .panel-header {
        flex-direction: column;
    }


    .quality-body {
        grid-template-columns: 1fr;
    }

}


@media (max-width: 520px) {

    .metric-grid {
        grid-template-columns: 1fr;
    }


    .timeline {
        padding-left: 12px;
        padding-right: 12px;
    }


    .investigation-list,
    .priority-list {
        padding-left: 12px;
        padding-right: 12px;
    }

}
"""


# ============================================================
# GRADIO APPLICATION
# ============================================================

with gr.Blocks(
    title="AI Security Warning Log Analyzer",
) as demo:

    gr.HTML(
        HEADER_HTML
    )


    # ========================================================
    # LOG INGESTION
    # ========================================================

    with gr.Group(
        elem_classes=["input-card"]
    ):

        gr.HTML(
            """
            <div class="input-title">
                Log Ingestion
            </div>

            <div class="input-description">
                File input takes priority over manual logs
            </div>
            """
        )

        with gr.Row():

            with gr.Column(
                scale=1
            ):

                gr.Markdown(
                    "### Upload Security Log"
                )

                file_input = gr.File(
                    label="Log file",
                    file_types=[
                        ".log",
                        ".txt",
                        ".csv",
                    ],
                    type="filepath",
                )

                gr.Markdown(
                    "Supported: LOG · TXT · CSV"
                )


            with gr.Column(
                scale=1
            ):

                gr.Markdown(
                    "### Manual Log Input"
                )

                manual_logs = gr.Textbox(
                    label="Textbox",

                    placeholder=(
                        "Paste security, authentication, "
                        "firewall, API, database, or "
                        "mixed logs here..."
                    ),

                    lines=12,

                    max_lines=24,

                    elem_classes=[
                        "manual-log-input"
                    ],
                )


        file_preview = gr.Textbox(
            visible=False,
            elem_id="file-preview",
        )


        with gr.Row():

            clear_button = gr.Button(
                "Clear",
                elem_classes=[
                    "clear-button"
                ],
            )

            analyze_button = gr.Button(
                "Analyze Logs",
                variant="primary",
                elem_classes=[
                    "analyze-button"
                ],
            )


    # ========================================================
    # DASHBOARD
    # ========================================================

    dashboard_output = gr.HTML(
        build_dashboard(None),
    )


    # ========================================================
    # DATA QUALITY
    # ========================================================

    data_quality_output = gr.HTML(
        "",
    )


    # ========================================================
    # AI ASSESSMENT
    # ========================================================

    ai_output = gr.HTML(
        "",
    )


    # ========================================================
    # TIMELINE
    # ========================================================

    timeline_output = gr.HTML(
        build_timeline([]),
    )


    # ========================================================
    # FINDINGS
    # ========================================================

    findings_output = gr.HTML(
        build_findings_table([]),
    )


    # ========================================================
    # INVESTIGATION
    # ========================================================

    investigation_output = gr.HTML(
        build_investigation([]),
    )


    # ========================================================
    # INVESTIGATION PRIORITIES
    # ========================================================

    investigation_priority_output = gr.HTML(
        build_investigation_priorities([]),
    )


    # ========================================================
    # RAW JSON
    # ========================================================

    gr.Markdown(
        """
        <div class="raw-json-heading">

            <div class="section-title">
                Raw Analysis JSON
            </div>

            <div class="section-subtitle">
                Machine-readable AI security assessment
            </div>

        </div>
        """
    )


    raw_json_output = gr.Code(
        value="{}",

        language="json",

        label="",

        elem_classes=[
            "raw-json"
        ],

        lines=20,
    )


    # ========================================================
    # EXPORT
    # ========================================================

    with gr.Row():

        export_report_button = gr.Button(
            "Export Report",
            elem_classes=[
                "export-button"
            ],
        )


    report_file = gr.File(
        label="Generated Security Report",
        interactive=False,
    )


    # ========================================================
    # EVENTS
    # ========================================================

    file_input.change(
        fn=load_file_preview,
        inputs=file_input,
        outputs=file_preview,
    )


    analyze_button.click(
        fn=analyze_logs,

        inputs=[
            file_input,
            manual_logs,
        ],

        outputs=[
            dashboard_output,
            data_quality_output,
            ai_output,
            timeline_output,
            findings_output,
            investigation_output,
            investigation_priority_output,
            raw_json_output,
        ],
    )


    export_report_button.click(
        fn=export_security_report,

        inputs=[
            raw_json_output,
        ],

        outputs=[
            report_file,
        ],
    )


    clear_button.click(
        fn=clear_all,

        inputs=[],

        outputs=[
            file_input,
            manual_logs,
            file_preview,
            dashboard_output,
            data_quality_output,
            ai_output,
            timeline_output,
            findings_output,
            investigation_output,
            investigation_priority_output,
            raw_json_output,
            report_file,
        ],
    )


# ============================================================
# LAUNCH
# ============================================================

if __name__ == "__main__":

    demo.launch(
        css=CSS,
        theme=gr.themes.Base(),
        show_error=True,
        run_history=True,
    )
