import json
import sys
from pathlib import Path


# Make the project root importable when this script is run directly.
PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from app.analyzer import analyze_log


DATASET_PATH = PROJECT_ROOT / "evaluation" / "security_cases.json"


RISK_LEVELS = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


CONSERVATIVE_TERMS = (
    "possible",
    "potential",
    "suspicious",
    "unconfirmed",
    "may",
    "might",
    "could",
    "requires investigation",
    "requires validation",
    "reported",
    "alleged",
    "claim",
    "uncertain",
    "uncertainty",
    "malformed timestamp",
    "invalid timestamp",
    "cannot be reliably placed",
    "cannot be reliably ordered",
)


CONFIRMED_TERMS = (
    "confirmed compromise",
    "system was compromised",
    "account was compromised",
    "attacker gained access",
    "successful attack",
)


MALICIOUS_REPETITION_TERMS = (
    "command and control",
    "command-and-control",
    "c2",
    "beaconing",
    "persistence",
)


def load_cases():
    """Load the evaluation dataset."""
    with DATASET_PATH.open(
        "r",
        encoding="utf-8",
    ) as file:
        return json.load(file)


def text_from_analysis(analysis):
    """
    Combine important AI output fields into searchable text.
    """
    parts = [
        str(
            analysis.get(
                "executive_summary",
                "",
            )
        ),
        str(
            analysis.get(
                "input_classification",
                "",
            )
        ),
    ]

    for finding in analysis.get("findings", []):
        if isinstance(finding, dict):
            parts.extend(
                [
                    str(finding.get("title", "")),
                    str(finding.get("description", "")),
                    str(finding.get("attack_pattern", "")),
                ]
            )

    for note in analysis.get(
        "data_quality_notes",
        [],
    ):
        parts.append(str(note))

    return " ".join(parts).lower()


def risk_exceeds(actual, maximum):
    """
    Return True when the actual risk is higher than the allowed maximum.
    """
    actual_value = RISK_LEVELS.get(
        str(actual).upper(),
        999,
    )

    maximum_value = RISK_LEVELS.get(
        str(maximum).upper(),
        -1,
    )

    return actual_value > maximum_value


def check_case(case, analysis):
    """
    Evaluate one analyzer result against the expectations
    defined in the dataset.
    """
    expected = case.get("expected", {})
    violations = []

    actual_classification = analysis.get(
        "input_classification"
    )

    allowed_classifications = expected.get(
        "input_classification",
        [],
    )

    if (
        allowed_classifications
        and actual_classification not in allowed_classifications
    ):
        violations.append(
            "input classification mismatch"
        )

    maximum_risk = expected.get(
        "overall_risk_not_above"
    )

    if maximum_risk and risk_exceeds(
        analysis.get("overall_risk"),
        maximum_risk,
    ):
        violations.append(
            "overall risk exceeds expected maximum"
        )

    allowed_confidence = expected.get(
        "confidence_allowed",
        [],
    )

    if (
        allowed_confidence
        and analysis.get("confidence")
        not in allowed_confidence
    ):
        violations.append(
            "overall confidence outside expected range"
        )

    combined_text = text_from_analysis(
        analysis
    )

    if expected.get(
        "must_not_confirm_compromise",
        False,
    ):
        if any(
            term in combined_text
            for term in CONFIRMED_TERMS
        ):
            violations.append(
                "unsupported compromise confirmation"
            )

    if expected.get(
        "must_use_conservative_language",
        False,
    ):
        if not any(
            term in combined_text
            for term in CONSERVATIVE_TERMS
        ):
            violations.append(
                "missing conservative uncertainty language"
            )

    if expected.get(
        "must_acknowledge_uncertainty",
        False,
    ):
        uncertainty_text = " ".join(
            [
                str(
                    analysis.get(
                        "executive_summary",
                        "",
                    )
                ),
                " ".join(
                    str(note)
                    for note in analysis.get(
                        "data_quality_notes",
                        [],
                    )
                ),
            ]
        ).lower()

        if not any(
            term in uncertainty_text
            for term in CONSERVATIVE_TERMS
        ):
            violations.append(
                "uncertainty not acknowledged"
            )

    if expected.get(
        "must_contain_security_finding",
        False,
    ):
        if not analysis.get("findings"):
            violations.append(
                "expected at least one security finding"
            )

    if expected.get(
        "must_identify_malformed_data",
        False,
    ):
        quality_text = " ".join(
            str(note)
            for note in analysis.get(
                "data_quality_notes",
                [],
            )
        ).lower()

        malformed_terms = (
            "malformed",
            "invalid timestamp",
            "invalid",
            "unusable timestamp",
        )

        if not any(
            term in quality_text
            for term in malformed_terms
        ):
            violations.append(
                "malformed data was not acknowledged"
            )

    if expected.get(
        "must_not_call_repetition_malicious",
        False,
    ):
        if any(
            term in combined_text
            for term in MALICIOUS_REPETITION_TERMS
        ):
            violations.append(
                "repeated legitimate activity treated as malicious"
            )

    return violations


def run_case(case):
    """
    Run one evaluation case.
    """
    case_id = case.get(
        "id",
        "unknown",
    )

    try:
        analysis = analyze_log(
            case["input"]
        )

        violations = check_case(
            case,
            analysis,
        )

        return {
            "id": case_id,
            "status": (
                "PASS"
                if not violations
                else "FAIL"
            ),
            "violations": violations,
            "actual": {
                "input_classification": analysis.get(
                    "input_classification"
                ),
                "overall_risk": analysis.get(
                    "overall_risk"
                ),
                "confidence": analysis.get(
                    "confidence"
                ),
                "finding_count": len(
                    analysis.get(
                        "findings",
                        [],
                    )
                ),
                "timeline_count": len(
                    analysis.get(
                        "timeline",
                        [],
                    )
                ),
                "priority_count": len(
                    analysis.get(
                        "investigation_priority",
                        [],
                    )
                ),
            },
        }

    except Exception as exc:
        return {
            "id": case_id,
            "status": "ERROR",
            "violations": [
                f"analyzer error: {exc}"
            ],
            "actual": {},
        }


def print_result(result):
    """
    Print a compact human-readable result.
    """
    status = result["status"]
    case_id = result["id"]

    print(
        f"[{status}] {case_id}"
    )

    actual = result.get(
        "actual",
        {},
    )

    if actual:
        print(
            "       "
            f"classification={actual.get('input_classification')} "
            f"risk={actual.get('overall_risk')} "
            f"confidence={actual.get('confidence')} "
            f"findings={actual.get('finding_count')} "
            f"timeline={actual.get('timeline_count')} "
            f"priorities={actual.get('priority_count')}"
        )

    for violation in result.get(
        "violations",
        [],
    ):
        print(
            f"       - {violation}"
        )


def main():
    cases = load_cases()

    print(
        "Security Analysis Evaluation"
    )
    print(
        "============================"
    )
    print(
        f"Evaluation cases: {len(cases)}"
    )
    print()

    results = []

    for case in cases:
        result = run_case(case)
        results.append(result)
        print_result(result)
        print()

    total = len(results)

    passed = sum(
        result["status"] == "PASS"
        for result in results
    )

    failed = sum(
        result["status"] == "FAIL"
        for result in results
    )

    errors = sum(
        result["status"] == "ERROR"
        for result in results
    )

    accuracy = (
        (passed / total) * 100
        if total
        else 0
    )

    print(
        "Evaluation Summary"
    )
    print(
        "=================="
    )
    print(
        f"Total cases: {total}"
    )
    print(
        f"Passed: {passed}"
    )
    print(
        f"Failed: {failed}"
    )
    print(
        f"Errors: {errors}"
    )
    print(
        f"Evaluation pass rate: {accuracy:.1f}%"
    )

    output_path = (
        PROJECT_ROOT
        / "evaluation"
        / "evaluation_results.json"
    )

    with output_path.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            {
                "total_cases": total,
                "passed": passed,
                "failed": failed,
                "errors": errors,
                "pass_rate_percent": round(
                    accuracy,
                    2,
                ),
                "results": results,
            },
            file,
            indent=2,
        )

    print()
    print(
        f"Detailed results written to: "
        f"{output_path}"
    )

    # Do not make the evaluation command fail simply because
    # the LLM produced an evaluation violation. The purpose of
    # this script is to collect evidence that we can inspect.
    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
