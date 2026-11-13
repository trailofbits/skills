from pathlib import Path
from typing import Literal

from calcifier import (
    Budget,
    agent,
    emit,
    fail,
    output_type,
    prepare_context,
    recipe,
    resource,
)

BASE = ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA")
ENV = (
    "CR",
    "IR",
    "AR",
    "MAV",
    "MAC",
    "MAT",
    "MPR",
    "MUI",
    "MVC",
    "MVI",
    "MVA",
    "MSC",
    "MSI",
    "MSA",
)
SUPPLEMENTAL = ("S", "AU", "R", "V", "RE", "U")
ORDER = BASE + ("E",) + ENV + SUPPLEMENTAL
VALUES = {
    "AV": ("N", "A", "L", "P"),
    "AC": ("L", "H"),
    "AT": ("N", "P"),
    "PR": ("N", "L", "H"),
    "UI": ("N", "P", "A"),
    "E": ("A", "P", "U"),
    "CR": ("H", "M", "L"),
    "IR": ("H", "M", "L"),
    "AR": ("H", "M", "L"),
    "S": ("P", "N"),
    "AU": ("Y", "N"),
    "R": ("A", "U", "I"),
    "V": ("D", "C"),
    "RE": ("L", "M", "H"),
    "U": ("Clear", "Green", "Amber", "Red"),
}
for_metric_values = ("H", "L", "N")
CALCULATOR = "https://www.first.org/cvss/calculator/4.0"


@output_type
class Metric:
    metric: str
    value: str
    justification: str
    assumed: bool


@output_type
class Calibration:
    example: str
    comparison: str


@output_type
class Assessment:
    disposition: Literal["scored", "clarification", "refused", "unsupported", "calculator"]
    response: str
    category: str
    facts: list[str]
    questions: list[str]
    uses_v31_vocabulary: bool
    mappings: list[str]
    metrics: list[Metric]
    calibration: list[Calibration]


def cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def allowed_values(metric: str) -> tuple[str, ...]:
    if metric in VALUES:
        return VALUES[metric]
    if metric in BASE:
        return for_metric_values
    if metric.startswith("M") and metric[1:] in BASE:
        if metric in ("MSI", "MSA"):
            return ("H", "L", "N", "S")
        return allowed_values(metric[1:])
    return ()


@recipe(
    name="cvss_scoring",
    version="1",
    agents=("worker",),
    budget=Budget(max_agent_calls=2, max_wall_seconds=3600),
)
def cvss_scoring(description: str) -> str:
    metrics_path = resource("references/metrics.md")
    examples_path = resource("references/examples.md")
    metrics_text = metrics_path.read_text(encoding="utf-8")
    examples_text = examples_path.read_text(encoding="utf-8")
    context = prepare_context(
        task=description,
        prior_results=(
            "Complete metric reference:\n"
            + metrics_text
            + "\n\nComplete calibration reference:\n"
            + examples_text
        ),
        instructions=(
            "Apply the authoritative cvss-scoring SKILL.md to this input in one connected "
            "session, preserving validation, fact extraction, ordered evaluation, calibration, "
            "and the final self-check. The complete references accompany this assignment. "
            "Use embedded text directly; read task.txt if the embedding is absent. "
            "Return structured decisions for deterministic rendering. Do not compute a score. "
            "For scored results, facts must contain the eight security-relevant fact answers "
            "in their specified order. Supply all base metrics and only evidenced optional "
            "metrics, with individual input-grounded justifications. For ambiguous impacts, "
            "explain plausible values and your defensible choice in the justification and "
            "set assumed=true. Do not silently assume uncertain exploitability: instead "
            "return clarification with the relevant fact-extraction questions and no metrics. "
            "Perform calibration against 2-3 most similar named examples, adjusting decisions "
            "as needed before returning final metrics. Explain consistency or justified "
            "divergence in each comparison. Keep the remaining reasoning and self-check "
            "internal. Acknowledge v3.1 vocabulary and supply its applied mappings. "
            "Use refused and category for a non-vulnerability; clarification for insufficient "
            "facts; unsupported with guidance if v3.1 or risk scoring is explicitly requested; "
            "calculator only for a request for the bare calculator. response contains any "
            "needed user-facing explanation, without a fabricated vector or numeric score. "
            "Use empty lists for inapplicable fields. Do not return optional X values."
        ),
    )
    result = agent(
        "worker",
        "Assess the complete assigned description under the original skill and return "
        "the requested structured decisions. References are available in full in context "
        "and through the declared read-only paths.",
        context=context,
        working_directory=Path("."),
        readable_paths=(metrics_path, examples_path),
        output=Assessment,
        timeout=3600,
    )
    preamble = []
    if result.uses_v31_vocabulary:
        if not result.mappings:
            fail("Version mismatch was detected but no translation explanation was supplied.")
        preamble.append(
            "Input uses CVSS v3.1 vocabulary; translating to v4.0 semantics. "
            "The following mappings were applied: " + "; ".join(result.mappings) + "."
        )
    if result.disposition != "scored":
        if result.disposition == "calculator":
            answer = CALCULATOR
        elif result.disposition == "refused":
            if not result.category.strip():
                fail("Refusal requires the category of the non-vulnerability finding.")
            answer = (
                "This description does not appear to describe an exploitable vulnerability. "
                "CVSS measures the severity of security weaknesses; it does not apply to "
                + result.category
                + ". If you believe there is an exploitable impact, "
                "restate the description in terms of attacker capability and re-run."
            )
        elif result.disposition == "clarification":
            if not result.questions or any(not q.strip() for q in result.questions):
                fail("An insufficient description requires concrete clarification questions.")
            answer = result.response + "\n\n" + "\n".join("- " + q for q in result.questions)
        else:
            if not result.response.strip():
                fail("An unsupported request requires explanatory guidance.")
            answer = result.response
        return emit("\n\n".join(preamble + [answer]), name="cvss-report")
    if len(result.facts) != 8 or any(not fact.strip() for fact in result.facts):
        fail("Scoring requires all eight security-relevant fact answers.")
    selected: dict[str, Metric] = {}
    for item in result.metrics:
        if item.metric in selected or item.metric not in ORDER:
            fail("Duplicate or unknown metric in assessment.")
        if item.value not in allowed_values(item.metric) or not item.justification.strip():
            fail("A metric has an invalid value or missing justification.")
        if item.assumed and item.metric in BASE[:5]:
            fail("Uncertain exploitability requires clarification before scoring.")
        selected[item.metric] = item
    if any(key not in selected for key in BASE):
        fail("Assessment omitted a required base metric.")
    if not 2 <= len(result.calibration) <= 3:
        fail("Calibration requires two or three examples.")
    for comparison in result.calibration:
        if not comparison.example.strip() or not comparison.comparison.strip():
            fail("Calibration requires named examples and substantive comparisons.")
        if comparison.example not in examples_text:
            fail("Calibration named an example absent from the supplied reference.")
    ordered = [selected[key] for key in ORDER if key in selected]
    vector = "CVSS:4.0/" + "/".join(item.metric + ":" + item.value for item in ordered)
    facts = "\n".join(str(i + 1) + ". " + fact for i, fact in enumerate(result.facts))
    rows = ["| Metric | Value | Justification |", "|--------|-------|---------------|"]
    for item in ordered:
        justification = item.justification
        if item.assumed and "[ASSUMED]" not in justification:
            justification += " [ASSUMED]"
        rows.append("| " + item.metric + " | " + item.value + " | " + cell(justification) + " |")
    notes = []
    if not any(key in selected for key in ENV):
        notes.append(
            "Environmental metrics omitted -- add if the target environment's CIA "
            "requirements differ from defaults."
        )
    if not any(key in selected for key in SUPPLEMENTAL):
        notes.append("Supplemental metrics omitted -- add for communication purposes if needed.")
    calibration = "\n".join(
        "- " + item.example + ": " + item.comparison for item in result.calibration
    )
    answer = "\n\n".join(
        preamble
        + [
            "Security-relevant facts\n\n" + facts,
            "Part 1: Metric Justification Table\n\n" + "\n".join(rows),
            "Part 2: Vector String\n\n" + vector + "\n" + CALCULATOR + "#" + vector,
            "\n\n".join(notes),
            "Part 3: Calibration Check\n\n" + calibration,
        ]
    )
    return emit(answer, name="cvss-report")


if __name__ == "__main__":
    raise SystemExit(cvss_scoring.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("404f6b4fe6c9a55fa6b0ba590d0f637b61688e3ed671c7fb3f719fab3a0ff5e0"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "references/examples.md",
        "sha256": ("45738f285bdc86b0380a06924f30813a00185ec55cf747b835fd9cb6cad5ac53"),
        "size": 13924,
        "source": None,
    },
    {
        "path": "references/metrics.md",
        "sha256": ("6c0ac5d5edb97810b819044b7d9e7c1c5f5a8a8791784e458d8463c0e4167c21"),
        "size": 14819,
        "source": None,
    },
]
_CALCIFIER_SUBRECIPES = []
