# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

import json
import math
from pathlib import Path
from shutil import which
from typing import Any, Literal

from calcifier import (
    Budget,
    agent,
    emit,
    fail,
    output_type,
    prepare_context,
    recipe,
    resource,
    run_command,
    step,
)

Operation = Literal[
    "extract",
    "individual",
    "team",
    "burnout",
    "compare",
    "motivators",
    "hiring",
    "coach",
    "predict",
    "debrief",
    "onboard",
    "conflict",
    "conversation",
]
ROUTES = {
    "extract": "extract-from-pdf",
    "individual": "interpret-individual",
    "team": "analyze-team",
    "burnout": "detect-burnout",
    "compare": "compare-profiles",
    "hiring": "define-hiring-profile",
    "coach": "coach-manager",
    "predict": "predict-from-interview",
    "debrief": "interview-debrief",
    "onboard": "plan-onboarding",
    "conflict": "mediate-conflict",
}
REFERENCES = (
    "primary-traits",
    "secondary-traits",
    "patterns-archetypes",
    "anti-patterns",
    "team-composition",
    "motivators",
    "conversation-starters",
    "interview-trait-signals",
)
ARCHETYPES = [
    "administrator",
    "coordinator",
    "craftsman",
    "daredevil",
    "debater",
    "facilitator",
    "influencer",
    "operator",
    "persuader",
    "philosopher",
    "rainmaker",
    "scholar",
    "socializer",
    "specialist",
    "technical-expert",
    "traditionalist",
    "trailblazer",
]


@output_type
class Report:
    title: str
    sections: list[tuple[str, str]]
    findings: tuple[str, str] | tuple[str, str, str]
    actions: list[str]


@output_type
class IndividualReport:
    report: Report
    strengths: tuple[str, str] | tuple[str, str, str]
    challenges: tuple[str, str] | tuple[str, str, str]


@output_type
class PrimaryPrediction:
    position: Literal["High", "Low", "Normative", "uncertain"]
    confidence: Literal["High", "Medium", "Low"]
    quotes: tuple[str, str] | tuple[str, str, str]


@output_type
class SecondaryPrediction:
    score: Literal[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10] | None
    confidence: Literal["High", "Medium", "Low"]
    quotes: tuple[str] | tuple[str, str]


@output_type
class PredictionReport:
    report: Report
    abcd: tuple[PrimaryPrediction, PrimaryPrediction, PrimaryPrediction, PrimaryPrediction]
    logic_ingenuity: tuple[SecondaryPrediction, SecondaryPrediction]


def number(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (float, int)) or not math.isfinite(value):
        fail(f"{label}: expected a finite number.")
    return float(value)


def chart_metrics(chart: Any, label: str) -> dict[str, Any]:
    if not isinstance(chart, dict):
        fail(f"{label}: expected a chart object.")
    arrow, eu = (number(chart.get(k), f"{label} {k}") for k in ("arrow", "eu"))
    relative, absolute, discrepancies = {}, {}, {}
    if not 0 <= arrow <= 10 or eu < 0 or not eu.is_integer():
        fail(f"{label}: arrow must be 0-10 and EU a nonnegative integer.")
    for trait in ("a", "b", "c", "d", "logic", "ingenuity"):
        values = chart.get(trait)
        if not isinstance(values, list) or len(values) != 2:
            fail(f"{label} {trait}: expected [absolute, relative] values.")
        score = number(values[0], f"{label} {trait}")
        if not 0 <= score <= 10 or not score.is_integer():
            fail(f"{label} {trait}: score must be an integer from 0 through 10.")
        absolute[trait] = score
        if trait in ("a", "b", "c", "d"):
            relative[trait] = number(values[1], f"{label} {trait} relative")
            computed = score - arrow
            if abs(computed - relative[trait]) > 0.000001:
                discrepancies[trait] = {"supplied": relative[trait], "calculated": computed}
    return {
        "arrow": arrow,
        "eu": eu,
        "relative": relative,
        "absolute": absolute,
        "distance_discrepancies": discrepancies,
        "leading_traits": sorted(relative, key=lambda trait: -abs(relative[trait])),
    }


@step
def load_profiles(paths: list[str], base: Path) -> dict[str, Any]:
    records, files = [], []
    for supplied in paths:
        path = (base / Path(supplied).expanduser()).resolve(strict=True)
        if not path.is_file() or path.suffix.lower() not in (".pdf", ".json"):
            fail(f"Expected a CI PDF or JSON file: {path}")
        files.append(str(path))
        selected = path.with_suffix(".json") if path.suffix.lower() == ".pdf" else path
        extracted = path.suffix.lower() == ".pdf" and not selected.is_file()
        if extracted:
            if which("uv") is None:
                fail("Install uv (brew install uv) before extraction; never estimate visually.")
            command = run_command(
                [
                    "uv",
                    "run",
                    "--no-project",
                    str(resource("scripts/extract_pdf.py")),
                    "--verify",
                    str(path),
                ],
                timeout_seconds=600,
                working_directory=path.parent,
                mutating=False,
            )
            if command.exit_code:
                fail(
                    "Extraction failed; fix dependencies, never estimate visually. "
                    + command.stderr
                    + command.stdout
                )
            data, summary = json.loads(command.stdout), command.stderr
        else:
            selected = selected.resolve(strict=True)
            files.append(str(selected))
            data, summary = json.loads(selected.read_text(encoding="utf-8")), ""
        items = data if isinstance(data, list) else [data]
        if not items:
            fail(f"{path}: the input contains zero profiles.")
        for item in items:
            if not isinstance(item, dict):
                fail(f"{path}: each profile must be an object.")
            survey = chart_metrics(item.get("survey"), f"{path} Survey")
            job = chart_metrics(item["job"], f"{path} Job") if item.get("job") is not None else None
            metrics: dict[str, Any] = {"survey": survey, "job": job}
            if job is not None:
                metrics["utilization"] = u = (
                    job["eu"] / survey["eu"] * 100 if survey["eu"] else None
                )
                metrics["energy_status"] = (
                    None
                    if u is None
                    else "stress"
                    if u > 130
                    else "frustration"
                    if u < 70
                    else "healthy"
                )
                metrics["arrow_change"] = job["arrow"] - survey["arrow"]
                metrics["movements"] = {
                    t: {
                        "absolute_change": job["absolute"][t] - survey["absolute"][t],
                        "relative_change": job["relative"][t] - survey["relative"][t],
                        "crossed_arrow": job["relative"][t] * survey["relative"][t] < 0,
                    }
                    for t in ("a", "b", "c", "d")
                }
                metrics["secondary_changes"] = {
                    t: job["absolute"][t] - survey["absolute"][t] for t in ("logic", "ingenuity")
                }
            records.append(
                {
                    "source": str(path),
                    "raw": item,
                    "metrics": metrics,
                    "extracted_here": extracted,
                    "verification_summary": summary,
                }
            )
    return {"profiles": records, "files": files}


@recipe(
    version="1",
    agents=("worker",),
    capabilities=("Bash",),
    budget=Budget(max_agent_calls=2, max_wall_seconds=3600),
)
def interpret_culture_index(
    operation: Operation,
    request: str = "",
    profile_files: list[str] | None = None,
    context_files: list[str] | None = None,
    working_directory: str = ".",
) -> str:
    base = Path(working_directory).expanduser().resolve(strict=True)
    loaded = load_profiles(profile_files or [], base)
    profiles = loaded["profiles"]
    minimum = 2 if operation in ("compare", "coach", "conflict") else 1
    if operation not in ("predict", "hiring", "debrief") and len(profiles) < minimum:
        fail(f"{operation} needs at least {minimum} complete CI profile(s).")
    if operation == "burnout" and any(p["metrics"]["job"] is None for p in profiles):
        fail("Burnout analysis requires Survey and Job charts for every profile.")
    support = tuple(
        (base / Path(p).expanduser()).resolve(strict=True) for p in (context_files or [])
    )
    if not profiles and not support and not request.strip():
        fail("Empty inspection scope: provide CI profiles, a transcript, or role context.")
    names = list(REFERENCES) + [f"archetype-{name}" for name in ARCHETYPES]
    references = [resource(f"references/{name}.md") for name in names]
    workflows = [ROUTES[operation]] if operation in ROUTES else []
    if operation == "debrief":
        workflows += ["predict-from-interview", "define-hiring-profile"]
    references += [resource(f"workflows/{name}.md") for name in workflows]
    files = tuple(dict.fromkeys(references + list(support) + [Path(p) for p in loaded["files"]]))
    counts = {
        role: sum(p["metrics"]["survey"]["relative"][t] > 0 for p in profiles)
        for role, t in (("Gas", "a"), ("Brake", "d"), ("Glue", "b"))
    }
    values = [
        dict(p["metrics"]["survey"]["absolute"], **p["metrics"]["survey"]["relative"])
        for p in profiles
    ]
    pairs = [
        {"left_index": i, "right_index": j, "gaps": {t: b[t] - a[t] for t in a}}
        for i, a in enumerate(values)
        for j, b in enumerate(values)
        if i < j
    ]
    observations = {"profiles": profiles, "right_of_arrow_counts": counts, "pairs": pairs}
    emit(observations, name="profile-data")
    context = prepare_context(
        f"Requested workflow: {operation}\nUser request/context:\n{request}",
        prior_results=json.dumps(observations, ensure_ascii=False, allow_nan=False),
        files=files,
        readable_roots=files,
        byte_budget=131072,
    )
    answer_type = (
        IndividualReport | str
        if operation == "individual"
        else PredictionReport | str
        if operation == "predict"
        else Report | str
    )
    answer = agent(
        "worker",
        "Perform the selected workflow's original reasoning, required readings, order, and checks "
        "in one session. Use full bundled inputs/references; read backing files when not embedded. "
        "Observations do not finish reasoning. Resolve discrepancies. Spot-check extracted_here "
        "PDFs against summaries: EU, arrows, extreme traits; never estimate scores visually. "
        "Return a blocker string if needed evidence/access is missing. Otherwise give the complete "
        "workflow report as heading/content sections with all tables and conditional deliverables. "
        "Individual: dedicated strengths/challenges. Predict: abcd=A/B/C/D, logic_ingenuity=L/I; "
        "with exact input quotes; omit the duplicate trait table. Keep original checks internal.",
        working_directory=base,
        readable_paths=files,
        context=context,
        output=answer_type,
        timeout=3600,
    )
    emit(answer, name="analysis")
    if isinstance(answer, str):
        fail(answer)
    report = answer.report if isinstance(answer, (IndividualReport, PredictionReport)) else answer
    texts = [
        report.title,
        *report.findings,
        *report.actions,
        *(x for section in report.sections for x in section),
    ]
    if not report.sections or not report.actions or any(not text.strip() for text in texts):
        fail("The analysis omitted required report content or recommendations.")
    parts = [f"# {report.title}"]
    if isinstance(answer, PredictionReport):
        parts += [
            "## Trait Predictions",
            "| Trait | Predicted | Confidence | Evidence |",
            "|---|---|---|---|",
        ]
        for label, prediction in zip(
            ("A", "B", "C", "D", "L", "I"),
            (*answer.abcd, *answer.logic_ingenuity),
            strict=True,
        ):
            value = (
                prediction.position
                if isinstance(prediction, PrimaryPrediction)
                else (prediction.score if prediction.score is not None else "uncertain")
            )
            evidence = " / ".join(prediction.quotes).replace("|", "\\|").replace("\n", " ")
            parts.append(f"| {label} | {value} | {prediction.confidence} | {evidence} |")
    parts += [f"## {title}\n\n{content}" for title, content in report.sections]
    if isinstance(answer, IndividualReport):
        parts += [
            "## Strengths",
            *[f"- {s}" for s in answer.strengths],
            "## Development Areas",
            *[f"- {s}" for s in answer.challenges],
        ]
    parts += [
        "Extraction complete" if operation == "extract" else "Interpretation complete",
        *[f"- {s}" for s in report.findings],
        "## Recommended Actions",
        *[f"- {s}" for s in report.actions],
    ]
    return emit("\n\n".join(parts), name="report")


if __name__ == "__main__":
    raise SystemExit(interpret_culture_index.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("fd777bfc802a216a0cfb15398ce14880e44250850096d19e3e45d58731932163"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "references/anti-patterns.md",
        "sha256": ("1d409d2823881adcec7caac2842773b5f60afaee7efb9435340e76da739f6be8"),
        "size": 8318,
        "source": None,
    },
    {
        "path": "references/archetype-administrator.md",
        "sha256": ("f445fcfb0ab566b162d0d5c13e01d6dcbca5f04085a0cba04b1863dd729832ea"),
        "size": 3786,
        "source": None,
    },
    {
        "path": "references/archetype-coordinator.md",
        "sha256": ("7061a34acb1e1bf33db4e16a088c83b1c0694bc1f152288853d66afb81a8e3e9"),
        "size": 4007,
        "source": None,
    },
    {
        "path": "references/archetype-craftsman.md",
        "sha256": ("c8ff07851b5635ff7df77dc4f392a9b2eb28fa4ffc34d856f8f7fbe571edd0d3"),
        "size": 3732,
        "source": None,
    },
    {
        "path": "references/archetype-daredevil.md",
        "sha256": ("51a0a11cd329b81ac50a29ef1fff10e16a35fda1d4df952d59f899b8e52a4eb6"),
        "size": 3388,
        "source": None,
    },
    {
        "path": "references/archetype-debater.md",
        "sha256": ("6c0bd2313b7a383e4ef999111c35ad9f1ea7f74b60bf4db4ff80952fa64b6d72"),
        "size": 4169,
        "source": None,
    },
    {
        "path": "references/archetype-facilitator.md",
        "sha256": ("eca1764fd0479968ec5aa0587ef0594f5f066151ef210fca0808e3c42e12dd43"),
        "size": 3818,
        "source": None,
    },
    {
        "path": "references/archetype-influencer.md",
        "sha256": ("5a239694848bdf257349e73fbc1ddd28f7b7b8bc8ce3b7436c3b62de91dd7ef2"),
        "size": 2919,
        "source": None,
    },
    {
        "path": "references/archetype-operator.md",
        "sha256": ("cf648a65c9b8bebbac0aefeabde13e19e6377ef77a201433f694af7fe62471d7"),
        "size": 3725,
        "source": None,
    },
    {
        "path": "references/archetype-persuader.md",
        "sha256": ("0dae3f16a10c378d271c52dd30273f2fc0b7f6d8055eeb19c583f77579764c9d"),
        "size": 3517,
        "source": None,
    },
    {
        "path": "references/archetype-philosopher.md",
        "sha256": ("303c023fc1eae6668a2d5ccd5984448fcbe4cb7b45b260ed42a96c877091a95a"),
        "size": 3675,
        "source": None,
    },
    {
        "path": "references/archetype-rainmaker.md",
        "sha256": ("106524ec470a7e5560ddfd28201bdf3a38f325d39fd4164fcb92395857726c5b"),
        "size": 2673,
        "source": None,
    },
    {
        "path": "references/archetype-scholar.md",
        "sha256": ("2d537ecbd557e797c6d76f1a54b4da586f964b08707cbad60b75418bd288f5ec"),
        "size": 4173,
        "source": None,
    },
    {
        "path": "references/archetype-socializer.md",
        "sha256": ("f7cbf91ad5c8380f735fb465da5bcef896e51bf448e30caae0505574eff3f412"),
        "size": 3403,
        "source": None,
    },
    {
        "path": "references/archetype-specialist.md",
        "sha256": ("b7a8aff7c3cd25e0906af607a0510c65b46d151230ffcd75dfe43092548aeb5c"),
        "size": 4237,
        "source": None,
    },
    {
        "path": "references/archetype-technical-expert.md",
        "sha256": ("631bccd9d0c2f5cba82e04e8f844ddd420a24ce36b4c654d90951b0294e8228e"),
        "size": 3783,
        "source": None,
    },
    {
        "path": "references/archetype-traditionalist.md",
        "sha256": ("f8bd3686ceb19a9eb127286507dc4c1c95d40c79e61636f980612df5462f58a5"),
        "size": 3745,
        "source": None,
    },
    {
        "path": "references/archetype-trailblazer.md",
        "sha256": ("e9e1f955d596f3195e26814b9ec65acf2bacaa7e36a18e8100ad40583a621447"),
        "size": 4119,
        "source": None,
    },
    {
        "path": "references/conversation-starters.md",
        "sha256": ("7b4eb68a07a2b074eb2f3aad2dfb10b243d3d029f3e531305b12952da05955dc"),
        "size": 9781,
        "source": None,
    },
    {
        "path": "references/interview-trait-signals.md",
        "sha256": ("36d86d19623326f30d61ea97acea0e0ce94d201fe8ced433bfcfe221244a6187"),
        "size": 8335,
        "source": None,
    },
    {
        "path": "references/motivators.md",
        "sha256": ("81ac045b0ab4d4d0740b20b83150c994ef787ca91a77aeead8ba76bb26228379"),
        "size": 6729,
        "source": None,
    },
    {
        "path": "references/patterns-archetypes.md",
        "sha256": ("dd580b448af3f10d83f6ecfda7ea36d205427aade07aeb641128aa71041dc18d"),
        "size": 6817,
        "source": None,
    },
    {
        "path": "references/primary-traits.md",
        "sha256": ("1279a1d0902ebbad344f1fb1aaa13cfcfd5a0a428610ccad07391b0adfcee50f"),
        "size": 12828,
        "source": None,
    },
    {
        "path": "references/secondary-traits.md",
        "sha256": ("d4443730129c42c0c9eb0eedfa007cdeb4507e59491d6399669daa754f538371"),
        "size": 8540,
        "source": None,
    },
    {
        "path": "references/team-composition.md",
        "sha256": ("256b77ccfdb2a4988dcbefd2dd5c4bd12eb597be2e17a12e36d8af6228ca2311"),
        "size": 6298,
        "source": None,
    },
    {
        "path": "scripts/check_deps.py",
        "sha256": ("db98f79ba2ae48b1957c4e22a2fb3420a4b36acf6747c4bdbfcc4acda8b1ceae"),
        "size": 2647,
        "source": None,
    },
    {
        "path": "scripts/culture_index/__init__.py",
        "sha256": ("7e98c16d427c278698d7414df956bec49d75d9d2bdc79b17998268a4ea9a3844"),
        "size": 564,
        "source": None,
    },
    {
        "path": "scripts/culture_index/constants.py",
        "sha256": ("8d35e6a5d22e72ced04885ea5e3a6c830f7c3c9c4a8037e874430bc056e5a7ec"),
        "size": 3724,
        "source": None,
    },
    {
        "path": "scripts/culture_index/extract.py",
        "sha256": ("7d890d69baad2622e760023e75eb291ade8414e0a0247d4d39c3a4792ebe5a4d"),
        "size": 5777,
        "source": None,
    },
    {
        "path": "scripts/culture_index/models.py",
        "sha256": ("47d62adc0581facc29dba3f31328f57901d2ad6eab7e71cdc60fd79e2aeed4c0"),
        "size": 371,
        "source": None,
    },
    {
        "path": "scripts/culture_index/opencv_extractor.py",
        "sha256": ("0e1b692c919dce97684031e506dc49db5a1a05833acf0b26ee9a1c71305c498a"),
        "size": 15966,
        "source": None,
    },
    {
        "path": "scripts/extract_pdf.py",
        "sha256": ("b3978d4d4d4aca8cb76474e9830771da676c14b99fb2b1a6a68da7f5388e8867"),
        "size": 7148,
        "source": None,
    },
    {
        "path": "scripts/pyproject.toml",
        "sha256": ("633a8eee9b475f1d849938b8f7a94f76b5f785997e8585090d188fcea1eb9174"),
        "size": 422,
        "source": None,
    },
    {
        "path": "scripts/uv.lock",
        "sha256": ("2858f87bd286628b353b6878b4a1fd666d7c850fbac5b317b11961fabd6d3735"),
        "size": 68183,
        "source": None,
    },
    {
        "path": "templates/burnout-report.md",
        "sha256": ("5eafbee230afd8a634cac6eec59467bd58edcd4c228b79cbf271a37a064dbbce"),
        "size": 3234,
        "source": None,
    },
    {
        "path": "templates/comparison-report.md",
        "sha256": ("860fe1c74bcd7197e7467172eb5043f6ecf2b20453a2e582ea1229b3841632e9"),
        "size": 3351,
        "source": None,
    },
    {
        "path": "templates/hiring-profile.md",
        "sha256": ("88659bedba664848f626f4f5268f12af27d0c67bbcb38c8ae7892704ba83083f"),
        "size": 4040,
        "source": None,
    },
    {
        "path": "templates/individual-report.md",
        "sha256": ("9bf72414b88b8d8aa5b8a4f0f47ab382bbd2f5bf394008a5ec7fdf94fe728018"),
        "size": 2589,
        "source": None,
    },
    {
        "path": "templates/predicted-profile.md",
        "sha256": ("7a41262b3f8d9a2ae78ce625abc32b4052ab11f2637715da75990205003fa9b2"),
        "size": 5718,
        "source": None,
    },
    {
        "path": "templates/team-report.md",
        "sha256": ("285c3aadd95ea640bf8f05e67394fbcf08546d73306c2d1e7b00a0f2717d491a"),
        "size": 3168,
        "source": None,
    },
    {
        "path": "workflows/analyze-team.md",
        "sha256": ("6c3f4197e89fe63ce952d84bbca4dd854d653611da672fe07a7479f3505848d0"),
        "size": 5250,
        "source": None,
    },
    {
        "path": "workflows/coach-manager.md",
        "sha256": ("0a85d1e8313a15ab72dab1fed127eedf295c7872c2922a536b72c7d4db66413c"),
        "size": 8999,
        "source": None,
    },
    {
        "path": "workflows/compare-profiles.md",
        "sha256": ("0565646cb48115b5559b1dd4ed984b932edfb64f796e87ff965091cab58e73b9"),
        "size": 6390,
        "source": None,
    },
    {
        "path": "workflows/define-hiring-profile.md",
        "sha256": ("158c94c591144eeb750791793aa430d27e226f4b5f0d1d93e852d585c44d4ef1"),
        "size": 7742,
        "source": None,
    },
    {
        "path": "workflows/detect-burnout.md",
        "sha256": ("057ac690ac791325c1a998d1a7a0492aac0bd9f0e6da8fb461ea40edd4cd8353"),
        "size": 6250,
        "source": None,
    },
    {
        "path": "workflows/extract-from-pdf.md",
        "sha256": ("200cdb731c59ac38f31b5b66e1dd5b70406699d33754d506b401fd8187a876ec"),
        "size": 3975,
        "source": None,
    },
    {
        "path": "workflows/interpret-individual.md",
        "sha256": ("73b4aac88682763f86632028dbdf770676a7e8de4b7dcd94d62b0a6afc9097f8"),
        "size": 5809,
        "source": None,
    },
    {
        "path": "workflows/interview-debrief.md",
        "sha256": ("4fa70a59ee0f0014b5ed7a76c6ee4837671a6f73b6ae331c4567fea95f857d64"),
        "size": 7681,
        "source": None,
    },
    {
        "path": "workflows/mediate-conflict.md",
        "sha256": ("09253a19ab9dc2bf207cc395400a84c0a977f8eb3e1794d75c846f81827d7232"),
        "size": 10146,
        "source": None,
    },
    {
        "path": "workflows/plan-onboarding.md",
        "sha256": ("82869f576c2260ac0baa05463c916f9583fecbe1fda756d2c78a39dca4491b53"),
        "size": 9447,
        "source": None,
    },
    {
        "path": "workflows/predict-from-interview.md",
        "sha256": ("f689863698e37244e17f2c2cceb4477b9abcf6725964d0eaf706a0989c107965"),
        "size": 8166,
        "source": None,
    },
]
_CALCIFIER_INTERFACE = {
    "text": (
        "The destination repository uses Ruff rules E, F, I, UP, B,"
        " and SIM, target-version py311, and line-length 100. The g"
        "enerated recipe must satisfy those checks, including B007,"
        " B905, and SIM102. Keep the Python 3.13 minimum required b"
        "y Calcifier in its generated PEP 723 header. This skill is"
        " distributed independently: do not require another unmerge"
        "d skill recipe. Referenced prose and explicitly provided r"
        "esources may be packaged, while the generated recipe belon"
        "gs only to the requested skill. Repository contribution ru"
        "le: a checker that inspects zero items must fail with an e"
        "xplanation rather than return a successful clean report. T"
        "his applies to an empty inspection scope, not to a complet"
        "ed inspection that finds zero issues."
    ),
    "sha256": ("12c73b0662a6bdb615688c499f4e3e22540e4788549e5ad24bb7e01f76c25fcc"),
}
_CALCIFIER_SUBRECIPES = []
