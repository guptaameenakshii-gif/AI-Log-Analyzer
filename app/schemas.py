from typing import Literal

from pydantic import BaseModel, Field, field_validator


Severity = Literal[
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "INFO",
]

Confidence = Literal[
    "HIGH",
    "MEDIUM",
    "LOW",
]

RiskLevel = Literal[
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "INFO",
]

InputClassification = Literal[
    "STRUCTURED",
    "UNSTRUCTURED",
    "MIXED",
    "INSUFFICIENT",
]


class TimelineEvent(BaseModel):
    @field_validator("severity", mode="before")
    @classmethod
    def normalize_source_severity(cls, value):
        if not isinstance(value, str):
            return value

        aliases = {
            "WARN": "MEDIUM",
            "WARNING": "MEDIUM",
            "ERROR": "HIGH",
            "ERR": "HIGH",
            "DEBUG": "INFO",
            "NOTICE": "INFO",
        }
        return aliases.get(value.strip().upper(), value)

    timestamp: str = Field(
        description=(
            "Timestamp exactly as observed in the input. "
            "Use 'Unknown' when no reliable timestamp exists."
        )
    )

    event: str = Field(
        description=(
            "Short factual description of the observed event. "
            "Do not state that an attack or incident is confirmed "
            "unless the evidence explicitly supports that conclusion."
        )
    )

    severity: Severity = Field(
        description=(
            "Severity of the observed event based only on available "
            "evidence. Severity does not represent confidence."
        )
    )

    evidence: str = Field(
        description=(
            "Concrete evidence from the supplied input, including "
            "the original log line where possible."
        )
    )

    line_number: int | None = Field(
        default=None,
        description=(
            "Original 1-based log line number when available."
        )
    )


class SecurityFinding(BaseModel):
    title: str = Field(
        description="Short security finding title."
    )

    severity: Severity = Field(
        description=(
            "Severity of the observed or credibly indicated security "
            "activity based on potential impact. Severity is independent "
            "of confidence: do not lower severity solely because "
            "confidence is low, and do not raise severity based only "
            "on alarming wording or an unverified claim."
        )
    )

    confidence: Confidence = Field(
        description=(
            "Confidence that this specific finding and its interpretation "
            "are supported by the supplied evidence. Use HIGH for direct, "
            "consistent evidence; MEDIUM for meaningful evidence with "
            "some uncertainty; LOW for incomplete, contradictory, "
            "indirect, or claim-based evidence."
        )
    )

    description: str = Field(
        description=(
            "Explain what the evidence directly shows, what it may mean, "
            "and what remains unverified. Distinguish attempted from "
            "successful activity, detection from execution, and blocking "
            "from successful compromise. Do not state an inferred outcome "
            "as fact."
        )
    )

    evidence: list[str] = Field(
        default_factory=list,
        description=(
            "Concrete observations from the supplied input that support "
            "this finding. Preserve the original meaning; do not invent, "
            "paraphrase a claim as telemetry, or cite unrelated events "
            "as proof."
        ),
    )

    attack_pattern: str = Field(
        description=(
            "Use a specific attack-pattern name only when supported by "
            "the evidence. Use 'Unclassified Suspicious Activity' when "
            "suspicious activity is evident but its specific pattern is "
            "unclear. Use 'Pattern Undetermined' when evidence is "
            "insufficient to characterize the activity. Do not imply "
            "successful execution or compromise without supporting evidence."
        )
    )

    recommended_actions: list[str] = Field(
        default_factory=list,
        description="Practical SOC investigation actions."
    )


class SecurityAnalysis(BaseModel):
    input_classification: InputClassification = Field(
        description=(
            "Classification of the supplied input: "
            "STRUCTURED, UNSTRUCTURED, MIXED, or INSUFFICIENT."
        )
    )

    data_quality_notes: list[str] = Field(
        default_factory=list,
        description=(
            "Important data-quality limitations including malformed "
            "records, contradictory events, missing timestamps, "
            "duplicates, or unverifiable claims."
        ),
    )

    executive_summary: str = Field(
        description=(
            "Concise executive-level assessment based only on "
            "supported evidence."
        )
    )

    overall_risk: RiskLevel = Field(
        description="Overall risk supported by the available evidence."
    )

    confidence: Confidence = Field(
        description="Overall confidence in the assessment."
    )

    findings: list[SecurityFinding] = Field(
        default_factory=list,
        description="Evidence-grounded security findings."
    )

    timeline: list[TimelineEvent] = Field(
        default_factory=list,
        description=(
            "Security-relevant events that have usable timestamps "
            "or are explicitly marked as undated."
        ),
    )

    investigation_priority: list[str] = Field(
        default_factory=list,
        description=(
            "Highest-priority investigation actions supported by "
            "the supplied evidence."
        ),
    )
