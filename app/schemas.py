from typing import Literal

from pydantic import BaseModel, Field


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
    timestamp: str = Field(
        description=(
            "Timestamp exactly as observed in the input. "
            "Use 'Unknown' when no reliable timestamp exists."
        )
    )

    event: str = Field(
        description="Short description of the observed event."
    )

    severity: Severity = Field(
        description="Severity supported by the available evidence."
    )

    evidence: str = Field(
        description="Concrete evidence from the supplied input."
    )


class SecurityFinding(BaseModel):
    title: str = Field(
        description="Short security finding title."
    )

    severity: Severity = Field(
        description="Severity based only on supplied evidence."
    )

    confidence: Confidence = Field(
        description="Confidence that the finding is supported by evidence."
    )

    description: str = Field(
        description="Evidence-grounded explanation of the finding."
    )

    evidence: list[str] = Field(
        default_factory=list,
        description=(
            "Concrete observations from the supplied input. "
            "Do not invent evidence."
        ),
    )

    attack_pattern: str = Field(
        description=(
            "Potential attack pattern supported by evidence, "
            "or exactly 'None identified'."
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
