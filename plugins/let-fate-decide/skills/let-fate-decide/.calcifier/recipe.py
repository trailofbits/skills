# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

import json
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
    run_command,
    step,
)


@output_type
class Card:
    suit: str
    card_id: str
    reversed: bool
    position: int
    role: str
    file: str
    content: str


@output_type
class House:
    house: int
    name: str
    focus: str
    file: str
    cards: list[Card]
    content: str


@output_type
class Spread:
    spread: str
    houses: list[House]
    entropy_bits: dict[str, float]
    entropy_note: str


@output_type
class Observations:
    reversal_count: int
    minor_suit_counts: dict[str, int]
    heavy_reversal_count: bool
    heavy_minor_suits: list[str]
    critical_major_placements: list[str]
    court_cards_in_people_houses: list[str]
    missing_card_files: list[str]


@output_type
class AppliedReading:
    interpretation: str
    action_result: str


@output_type
class PortentReading:
    dominant_theme: str
    main_risk_or_blind_spot: str
    recommended_next_action: str


@step
def draw_and_check(directory: str) -> Spread:
    spread = run_command(
        ["uv", "run", "--no-config", str(resource("scripts/draw_cards.py")), "--content"],
        timeout_seconds=60,
        working_directory=directory,
        mutating=False,
        output=Spread,
    )
    if spread.spread != "12 Houses of the Zodiac" or len(spread.houses) != 12:
        fail("The draw did not contain the required 12-house spread; skip the reading.")
    seen: set[str] = set()
    roles = ("major_arcana", "minor_arcana_1", "minor_arcana_2")
    for number, house in enumerate(spread.houses, start=1):
        if house.house != number or len(house.cards) != 3:
            fail("The draw has an incomplete or unordered house; skip the reading.")
        if not house.content.strip() or house.content.startswith("(error reading reference file "):
            fail(f"Cannot read required house meaning: {house.file}")
        for offset, card in enumerate(house.cards):
            if card.position != 3 * (number - 1) + offset + 1 or card.role != roles[offset]:
                fail("The draw has invalid card positions or roles; skip the reading.")
            if card.suit not in ("major", "wands", "cups", "swords", "pentacles"):
                fail("The draw has an unknown suit; skip the reading.")
            if (card.suit == "major") != (offset == 0):
                fail("Each house must contain one Major followed by two Minor Arcana cards.")
            if card.file != f"cards/{card.suit}/{card.card_id}.md" or card.file in seen:
                fail("The draw has an inconsistent or duplicate card; skip the reading.")
            if not card.content.strip():
                fail(f"The card meaning is empty: {card.file}")
            seen.add(card.file)
    return spread


@step
def observe(spread: Spread) -> Observations:
    cards = [card for house in spread.houses for card in house.cards]
    if not cards:
        fail("No cards were available to inspect; an empty scope cannot produce a reading.")
    suits = {suit: 0 for suit in ("wands", "cups", "swords", "pentacles")}
    critical: list[str] = []
    people: list[str] = []
    missing: list[str] = []
    weighty = ("13-death", "16-the-tower", "15-the-devil", "20-judgement", "21-the-world")
    courts = ("page", "knight", "queen", "king")
    for house in spread.houses:
        for card in house.cards:
            placement = f"House {house.house}: {card.card_id}"
            if card.suit != "major":
                suits[card.suit] += 1
            if house.house in (1, 8, 12) and card.card_id in weighty:
                critical.append(placement)
            if house.house in (3, 7, 11) and card.card_id.split("-", 1)[0] in courts:
                people.append(placement)
            if card.content.startswith("(error reading card file "):
                missing.append(card.file)
    reversals = sum(card.reversed for card in cards)
    return Observations(
        reversal_count=reversals,
        minor_suit_counts=suits,
        heavy_reversal_count=reversals >= 24,
        heavy_minor_suits=[suit for suit, count in suits.items() if count >= 10],
        critical_major_placements=critical,
        court_cards_in_people_houses=people,
        missing_card_files=missing,
    )


@recipe(
    name="let-fate-decide",
    version="1",
    capabilities=("Bash",),
    agents=("worker",),
    budget=Budget(max_agent_calls=2, max_wall_seconds=3600),
)
def let_fate_decide(
    task: str,
    working_directory: str = ".",
    answer_mode: Literal["task", "portent"] = "task",
) -> str:
    if not task.strip():
        fail("Provide a nonempty task or decision point; there is no scope to interpret.")
    project = Path(working_directory).resolve()
    if not project.is_dir():
        fail("The working directory must be an existing directory.")
    spread = draw_and_check(str(project))
    observations = observe(spread)
    emit(spread, name="draw")
    references = [
        resource("references/INTERPRETATION_GUIDE.md"),
        resource("references/TECHNICAL_CONTEXT_LENSES.md"),
    ]
    if answer_mode == "portent":
        references.append(resource("agents/draw.md"))
    instructions = (
        "Handle this single decision point under the authoritative source skill. "
        "Python has executed the supplied drawing program once with --content. "
        "The draw contains the complete house and card texts, orientations, and ordering. "
        "Read those complete texts and the complete supplied references; the computed "
        "observations are mechanical aids, not an interpretation or a candidate filter. "
        "Use embedded context directly; if it is not embedded completely, read task.txt "
        "and the context files in full. Apply the original applicability limits. "
        "Keep the original reasoning workflow, interpretation, and follow-through in "
        "this session, covering all 12 houses and applying relevant technical lenses. "
        "Do not redraw or simulate entropy. Identify any reported missing card files "
        "and apply the source's name-and-suit fallback for those cards. "
        "Include the interpretation alongside your next tool call implementing the "
        "chosen option, then report its actual outcome. Perform the engineering "
        "verification required for security or correctness work; distinguish evidence "
        "obtained from follow-up still needed. Never claim an unperformed action or "
        "validation succeeded. Work only within the user's authorized task. "
        "If the source excludes Tarot here, honor its alternative guidance and explain "
        "the disposition without treating the draw as authority. If a required tool "
        "is unavailable, report the missing capability instead of claiming completion."
    )
    context = prepare_context(
        task,
        instructions=instructions,
        prior_results=json.dumps(
            {"draw": spread.model_dump(), "observations": observations.model_dump()},
            ensure_ascii=False,
        ),
        files=tuple(references),
        readable_roots=tuple(references),
    )
    if answer_mode == "portent":
        portent = agent(
            "worker",
            "Complete the assigned workflow. Return three concise fields for the "
            "dominant theme, main risk or blind spot, and recommended next action. "
            "The action field should also convey the implementing action's actual outcome.",
            context=context,
            working_directory=project,
            readable_paths=(project,),
            writable_paths=(project,),
            required_capabilities=("commands",),
            output=PortentReading,
            timeout=3600,
        )
        bullets = [
            portent.dominant_theme,
            portent.main_risk_or_blind_spot,
            portent.recommended_next_action,
        ]
        if any(not value.strip() for value in bullets):
            fail("The agent omitted a required portent bullet.")
        report = "\n".join("- " + " ".join(value.split()) for value in bullets)
    else:
        reading = agent(
            "worker",
            "Complete the assigned workflow. Return the synthesized interpretation "
            "and the concrete implementing action's outcome, including material "
            "verification results or unresolved limitations.",
            context=context,
            working_directory=project,
            readable_paths=(project,),
            writable_paths=(project,),
            required_capabilities=("commands",),
            output=AppliedReading,
            timeout=3600,
        )
        if not reading.interpretation.strip() or not reading.action_result.strip():
            fail("The agent omitted the interpretation or action outcome.")
        report = reading.interpretation.strip() + "\n\n" + reading.action_result.strip()
    return emit(report, name="reading")


if __name__ == "__main__":
    raise SystemExit(let_fate_decide.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("effc5f0be27d62d7a708fa54cd630ea0fe1a6609a0366797f70c388bc4c6df71"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "agents/draw.md",
        "sha256": ("b21951ced1891d221c6ee01752d8af1d96a88d2e7b2e5e68d5f1ca394bd7afbb"),
        "size": 1799,
        "source": "../../agents/draw.md",
    },
    {
        "path": "cards/cups/ace-of-cups.md",
        "sha256": ("28d860f3fd39dac5406720bfef368290c6edcd94b7f0d1b4082ef2aae019f335"),
        "size": 627,
        "source": None,
    },
    {
        "path": "cards/cups/eight-of-cups.md",
        "sha256": ("052d9dcc01ade4751b64f030eebcd426e2b2ab70936c23a74375d6851f6e0912"),
        "size": 666,
        "source": None,
    },
    {
        "path": "cards/cups/five-of-cups.md",
        "sha256": ("01e940a53c713178583a2932b6a870095de33088a581c5d557c2aeba7ce4bf16"),
        "size": 603,
        "source": None,
    },
    {
        "path": "cards/cups/four-of-cups.md",
        "sha256": ("d62d23ecb21a6c83a8067084b78eb8381eac9f9f0a33826205f3c6d9ab8e5e61"),
        "size": 607,
        "source": None,
    },
    {
        "path": "cards/cups/king-of-cups.md",
        "sha256": ("31ac9ef71d086129ca8a10c3a01a6ed72e7ec1d2c97bf88080e000a19ec65cac"),
        "size": 511,
        "source": None,
    },
    {
        "path": "cards/cups/knight-of-cups.md",
        "sha256": ("0994326d74e1898ab15f797e83815300164117c8288f1ba146ebe8931b5705e3"),
        "size": 478,
        "source": None,
    },
    {
        "path": "cards/cups/nine-of-cups.md",
        "sha256": ("4582d5108dc8ad76279a78074f8d7cc7fb22c159c68c49dc091dbdfd118df4a7"),
        "size": 634,
        "source": None,
    },
    {
        "path": "cards/cups/page-of-cups.md",
        "sha256": ("2f5583c906d94e33848e714fbf1211c1fcf02d1e2ccb5f5e4d3ec92e4e34dc85"),
        "size": 518,
        "source": None,
    },
    {
        "path": "cards/cups/queen-of-cups.md",
        "sha256": ("40fa2d0fa5b72659caff71bf7eafa77a2428e5ecfebf69f741ade33232167c3e"),
        "size": 502,
        "source": None,
    },
    {
        "path": "cards/cups/seven-of-cups.md",
        "sha256": ("852b35c0058d6e929af96ea6a567727803bdba75578310d193c837a29df450a2"),
        "size": 497,
        "source": None,
    },
    {
        "path": "cards/cups/six-of-cups.md",
        "sha256": ("6f2ade658b7681ba77e444932deb7f909e5d3d9618d9cb73b1503305a2726ecb"),
        "size": 496,
        "source": None,
    },
    {
        "path": "cards/cups/ten-of-cups.md",
        "sha256": ("ac8dc9d3cf2a9d020c35369af76eb8874a8ef21a2911111739fb87f3cb4ea926"),
        "size": 536,
        "source": None,
    },
    {
        "path": "cards/cups/three-of-cups.md",
        "sha256": ("9c801eb74f5cf5c76e69df620f3fccbf29dd2db50351737d326735fde77d3043"),
        "size": 482,
        "source": None,
    },
    {
        "path": "cards/cups/two-of-cups.md",
        "sha256": ("b10857cbdc7cca86805bf4a06c38cd504fd2c6577b3549b8b64a00156e92b148"),
        "size": 500,
        "source": None,
    },
    {
        "path": "cards/major/00-the-fool.md",
        "sha256": ("41575fb537544bb1cf50a85e7d3d42cc198ee5f72019b2863de222e1a8ac5116"),
        "size": 563,
        "source": None,
    },
    {
        "path": "cards/major/01-the-magician.md",
        "sha256": ("860c04ab0c9b562284aec2aebbba223900545abc79cd3819713ed3bad9eb7dfd"),
        "size": 648,
        "source": None,
    },
    {
        "path": "cards/major/02-the-high-priestess.md",
        "sha256": ("26a10ab90842bb85a7890d3d9856b383fb33f8b417a70a30c0c0a054088c14c6"),
        "size": 710,
        "source": None,
    },
    {
        "path": "cards/major/03-the-empress.md",
        "sha256": ("b7be52dff834f93f38e2a2f0e69c8e036043c9119d9ac1f391601db19bcd0ddb"),
        "size": 645,
        "source": None,
    },
    {
        "path": "cards/major/04-the-emperor.md",
        "sha256": ("1b48cba12beed161b3d9337ad3591b5b2200d13f7d8559ecd22fc4f183fb603b"),
        "size": 651,
        "source": None,
    },
    {
        "path": "cards/major/05-the-hierophant.md",
        "sha256": ("cdc24f287b1eda5074053fd1ea63e8c1deae6db9bf02063713222807416d0144"),
        "size": 685,
        "source": None,
    },
    {
        "path": "cards/major/06-the-lovers.md",
        "sha256": ("9722ff4c624be5b7693b947661135c04b1a76402f7490088c04256a44f40225e"),
        "size": 715,
        "source": None,
    },
    {
        "path": "cards/major/07-the-chariot.md",
        "sha256": ("fd9f65cd6785b54e6417fe1adc49273cce0adb70c2a002fea92a25cdeb27bd6b"),
        "size": 704,
        "source": None,
    },
    {
        "path": "cards/major/08-strength.md",
        "sha256": ("cca5b9f50d8a5d54b552fbe731b43d88c6cceb3c2006b11611f0274975a21d27"),
        "size": 689,
        "source": None,
    },
    {
        "path": "cards/major/09-the-hermit.md",
        "sha256": ("9d747c35f2e2c02272917ee1e710ee51269bf8edc9e304d7c4354f354d3f8112"),
        "size": 644,
        "source": None,
    },
    {
        "path": "cards/major/10-wheel-of-fortune.md",
        "sha256": ("52f5250e71884999ab6669bf5dc0b24a0585d0ae6acefcada03300d58e3a181a"),
        "size": 723,
        "source": None,
    },
    {
        "path": "cards/major/11-justice.md",
        "sha256": ("3c9967f413166c306cde202ecec98f82ce17eb01c0ee78b70e9f2ecece59fe3d"),
        "size": 664,
        "source": None,
    },
    {
        "path": "cards/major/12-the-hanged-man.md",
        "sha256": ("2843c5b45356afe26adbcd5403af85228f167cdca2fbced6b1ad54e8d556f4ff"),
        "size": 709,
        "source": None,
    },
    {
        "path": "cards/major/13-death.md",
        "sha256": ("f52aac25b735b0f77bf5c8dac58226c88366a75ab4973ae7487498d8d6b3c6b9"),
        "size": 702,
        "source": None,
    },
    {
        "path": "cards/major/14-temperance.md",
        "sha256": ("05514fd17d45073655d6a878f0f2a70af48002669c4981433af10405478ad3c8"),
        "size": 706,
        "source": None,
    },
    {
        "path": "cards/major/15-the-devil.md",
        "sha256": ("534d78dc4904ba055060bb9d0d4bb53eb3f9a957cd247a211a2ef46d47b3d045"),
        "size": 699,
        "source": None,
    },
    {
        "path": "cards/major/16-the-tower.md",
        "sha256": ("c1ffa1d2b31353604e8171642bd86fa52700b2d9fcf88770391a4b8bcb4a9b05"),
        "size": 723,
        "source": None,
    },
    {
        "path": "cards/major/17-the-star.md",
        "sha256": ("0cc63419420005e0b67d9c6b9cc472734ae1806eb370222d258abe1257d6f303"),
        "size": 653,
        "source": None,
    },
    {
        "path": "cards/major/18-the-moon.md",
        "sha256": ("48a5ae8586a1396ca6e7669ae63ae12a96095e724d390d9ae9906c8422ab3733"),
        "size": 759,
        "source": None,
    },
    {
        "path": "cards/major/19-the-sun.md",
        "sha256": ("10321c73be2c4451404e5ded4c33b1fa6c702602dc101d40e3b31f86c07ad08e"),
        "size": 722,
        "source": None,
    },
    {
        "path": "cards/major/20-judgement.md",
        "sha256": ("c78b987db4cbc5f521628adcd166b0231dc2ec1ee3c2bdb3e80a4aedec5cec98"),
        "size": 701,
        "source": None,
    },
    {
        "path": "cards/major/21-the-world.md",
        "sha256": ("ccef15a05bcf6d3d8e6720e2f671665ac0994db99aaee64384878847d0e02062"),
        "size": 731,
        "source": None,
    },
    {
        "path": "cards/pentacles/ace-of-pentacles.md",
        "sha256": ("1caba9776a0adcc3f7d3e6daadde15a53e8d46a5297071f5bd21fbec40e65fa4"),
        "size": 458,
        "source": None,
    },
    {
        "path": "cards/pentacles/eight-of-pentacles.md",
        "sha256": ("0b3de585f8a1c61466d858ed8d9c20cfc8c9811e8bfabbe41e624bbcc21cba46"),
        "size": 486,
        "source": None,
    },
    {
        "path": "cards/pentacles/five-of-pentacles.md",
        "sha256": ("f87ad3474db7ae1941262639adf31fdf86504e7f9dd0b807b735aaf46425d130"),
        "size": 427,
        "source": None,
    },
    {
        "path": "cards/pentacles/four-of-pentacles.md",
        "sha256": ("018c3298cb17bce1bbe47beda6feb34d9095712de7ecf6f20aa35cfb7074487f"),
        "size": 436,
        "source": None,
    },
    {
        "path": "cards/pentacles/king-of-pentacles.md",
        "sha256": ("ee2168eb3a385b708bbcbb26f28ded67624a15a196c41ff58119b86a7f925576"),
        "size": 459,
        "source": None,
    },
    {
        "path": "cards/pentacles/knight-of-pentacles.md",
        "sha256": ("260d740f2176d5c8810a8a3d0713331e84816a21987f41519a36579c026585a2"),
        "size": 471,
        "source": None,
    },
    {
        "path": "cards/pentacles/nine-of-pentacles.md",
        "sha256": ("76bdee95c610950fdf777a353d5b5a675c44c6549840c3bfe80f8dea369535ce"),
        "size": 447,
        "source": None,
    },
    {
        "path": "cards/pentacles/page-of-pentacles.md",
        "sha256": ("adf518c7d4b4e10e1f2414986916339fc7990dd01ddc7ccb90986722533ecc88"),
        "size": 465,
        "source": None,
    },
    {
        "path": "cards/pentacles/queen-of-pentacles.md",
        "sha256": ("c48f3b2e0cbc6f11cd1e70eedbb694a23d0747be4166eb2a190a9e9e7b98a547"),
        "size": 452,
        "source": None,
    },
    {
        "path": "cards/pentacles/seven-of-pentacles.md",
        "sha256": ("04a5ff396864508c33021d4c47b62d1b17f4a30a5a08523402ffc9974cb841f0"),
        "size": 461,
        "source": None,
    },
    {
        "path": "cards/pentacles/six-of-pentacles.md",
        "sha256": ("bb3a9210f5d3b2d9f4b64aab0488ea828dc0644570c3af4438091e1c85bb9fc5"),
        "size": 428,
        "source": None,
    },
    {
        "path": "cards/pentacles/ten-of-pentacles.md",
        "sha256": ("04f25f877dce74a5dd1bffe356f49b8824d30165c63e01792c724f1e6423299a"),
        "size": 459,
        "source": None,
    },
    {
        "path": "cards/pentacles/three-of-pentacles.md",
        "sha256": ("462c3ac0bb6e44f1783f9324982c2fce31835dc3a341ce9a43c3f49a307ff498"),
        "size": 468,
        "source": None,
    },
    {
        "path": "cards/pentacles/two-of-pentacles.md",
        "sha256": ("b3f0d48efe23625b4a903d6c8b1eac3dabd892bf8447f25adc486e2266294464"),
        "size": 448,
        "source": None,
    },
    {
        "path": "cards/swords/ace-of-swords.md",
        "sha256": ("4b0fce4e8fb09df62ffd62cdb09150ff8c03c6e6719626ab418fdb6ea7038f2a"),
        "size": 477,
        "source": None,
    },
    {
        "path": "cards/swords/eight-of-swords.md",
        "sha256": ("24e30c870eae818039da9b8f72fb53af1335a351567a1f26c79554b176db1222"),
        "size": 508,
        "source": None,
    },
    {
        "path": "cards/swords/five-of-swords.md",
        "sha256": ("db3be74d50cdcbac72afcbffdbb5912d867a2792288b77d63a1512a962e18042"),
        "size": 498,
        "source": None,
    },
    {
        "path": "cards/swords/four-of-swords.md",
        "sha256": ("4b0482f235b8f0f9f42655b4217eb39e0a8bc39118f4e4e1a0d0054d098d0d68"),
        "size": 453,
        "source": None,
    },
    {
        "path": "cards/swords/king-of-swords.md",
        "sha256": ("f84ef817a08822df4ec1dc97dbffd0834d88ddbba0a61fdbdda0c8491ec348a1"),
        "size": 518,
        "source": None,
    },
    {
        "path": "cards/swords/knight-of-swords.md",
        "sha256": ("c09c1ee07d279e676e190172ed236f64da85fbe429fd8dc54956ff0f69f7e71a"),
        "size": 615,
        "source": None,
    },
    {
        "path": "cards/swords/nine-of-swords.md",
        "sha256": ("a8a8d683cf8c4027ba2e8cc4cafd060c7e6a20f333bba35e9eb6aa4c49243027"),
        "size": 597,
        "source": None,
    },
    {
        "path": "cards/swords/page-of-swords.md",
        "sha256": ("3aed5fc3d3f31be5ce606cbbcb8be464921abb578b5f56bd602e47caa59ce415"),
        "size": 504,
        "source": None,
    },
    {
        "path": "cards/swords/queen-of-swords.md",
        "sha256": ("0b757ae9f04cf6aa3fc3884cb6703e4db83e9998c1d79d155fec6d0208f74252"),
        "size": 517,
        "source": None,
    },
    {
        "path": "cards/swords/seven-of-swords.md",
        "sha256": ("f0bb09b5ee7ffe2c5b8c11699414d257f5b4ecf1b191ac583e4c3891e5f9ed6b"),
        "size": 495,
        "source": None,
    },
    {
        "path": "cards/swords/six-of-swords.md",
        "sha256": ("a9dae20e46b5001ab4dc79001d5c79574307b869e0915bc17cad73824227c633"),
        "size": 494,
        "source": None,
    },
    {
        "path": "cards/swords/ten-of-swords.md",
        "sha256": ("0c17b735e0688f0c0cdc27e78b257fb49ac9496b0f0cc023c08a0cbeddbd865f"),
        "size": 612,
        "source": None,
    },
    {
        "path": "cards/swords/three-of-swords.md",
        "sha256": ("2dbf184dc19636aafb143796ada0cc4dc3a5fbb3759a7ce47bb14d0ebe8894b1"),
        "size": 457,
        "source": None,
    },
    {
        "path": "cards/swords/two-of-swords.md",
        "sha256": ("a633f81bd06573f81668d1d26d9b2056b6ecce356995d71544cb96c7f268224d"),
        "size": 497,
        "source": None,
    },
    {
        "path": "cards/wands/ace-of-wands.md",
        "sha256": ("39e3e3d2a8d8b0d87451aee977bbe83a84b9c86283f0a42e0d5b24dd1e255467"),
        "size": 461,
        "source": None,
    },
    {
        "path": "cards/wands/eight-of-wands.md",
        "sha256": ("f3fa34b26e1051c78650d2bf1d78a252ce01845efb07b68a783dff3cb0b0549c"),
        "size": 443,
        "source": None,
    },
    {
        "path": "cards/wands/five-of-wands.md",
        "sha256": ("7e5d05f4b2ee9d1f70dd5bceb358ff4b2ac4445425f8ef63697af781bcd772f9"),
        "size": 482,
        "source": None,
    },
    {
        "path": "cards/wands/four-of-wands.md",
        "sha256": ("66bd9b79fbb299e68edc0c56c2907f974bdd301c1c69209a573567ae8743302b"),
        "size": 461,
        "source": None,
    },
    {
        "path": "cards/wands/king-of-wands.md",
        "sha256": ("78b9eb4077c37bffa93ee9a6fba829ad456a7d6b459c9e9131fe58b332ab27d7"),
        "size": 467,
        "source": None,
    },
    {
        "path": "cards/wands/knight-of-wands.md",
        "sha256": ("f05410f1edfff2d3645f35f41589b69b695dbe640f4c02f549b4c5ad88c97427"),
        "size": 547,
        "source": None,
    },
    {
        "path": "cards/wands/nine-of-wands.md",
        "sha256": ("32f4908e9699dc4d038a702f6104cf27bb4332144570103b0e6db2a7fa58215c"),
        "size": 414,
        "source": None,
    },
    {
        "path": "cards/wands/page-of-wands.md",
        "sha256": ("6da5cc15d95cf5d71b8dc3082d250e32d90b77358d20bf531c671c8e6c39e6f8"),
        "size": 449,
        "source": None,
    },
    {
        "path": "cards/wands/queen-of-wands.md",
        "sha256": ("de284467b8ce9520abb13b7fd3a2f4e76dfd6550940aca7d6664ea8f6fdb0644"),
        "size": 466,
        "source": None,
    },
    {
        "path": "cards/wands/seven-of-wands.md",
        "sha256": ("396b64b16a31d73094f564501e5739b6ca27155844d9edd6fd1e686b1d9181b6"),
        "size": 525,
        "source": None,
    },
    {
        "path": "cards/wands/six-of-wands.md",
        "sha256": ("d96d44e0834a8620d9f9e29e3ffaeba40ecbbbaf47647a366161a24d51715e93"),
        "size": 587,
        "source": None,
    },
    {
        "path": "cards/wands/ten-of-wands.md",
        "sha256": ("85a48ee300d19ac5891bbe0787674431cf06393cee053e056936d6a09d6e4690"),
        "size": 438,
        "source": None,
    },
    {
        "path": "cards/wands/three-of-wands.md",
        "sha256": ("b058a8184bf119f0cc10bbc7a08ca3320984e3b9cbd316eb02c3525b51245450"),
        "size": 464,
        "source": None,
    },
    {
        "path": "cards/wands/two-of-wands.md",
        "sha256": ("e91a11e478106f0bf7660dc8cc60ba970742f75dc4b64f761871ff57bdd9d84e"),
        "size": 445,
        "source": None,
    },
    {
        "path": "houses/01-first-house.md",
        "sha256": ("fbb8cd604285efddadc10441e11e7e591dccbda7d4ad400deda27537d553580e"),
        "size": 1448,
        "source": None,
    },
    {
        "path": "houses/02-second-house.md",
        "sha256": ("ddad48b51cea49cd217777ab09544ade33620146954448790a4329dd0b346ce7"),
        "size": 1550,
        "source": None,
    },
    {
        "path": "houses/03-third-house.md",
        "sha256": ("5548da8f7f93eb478d8863fed36d24233050a9b67b2e33e0fc17e2e5a8adb044"),
        "size": 1350,
        "source": None,
    },
    {
        "path": "houses/04-fourth-house.md",
        "sha256": ("722f2dd5834a91ceef2c060e966c3caa514ec2afd7204bd6e0a0c5912d2918bc"),
        "size": 1637,
        "source": None,
    },
    {
        "path": "houses/05-fifth-house.md",
        "sha256": ("b7e8a9a6d7746152072c23bae63800354744bdd082cf4c23d997a1c602ab4fe9"),
        "size": 1548,
        "source": None,
    },
    {
        "path": "houses/06-sixth-house.md",
        "sha256": ("7333745972dbff4f31cad1b42afcd4a2f577c2fdd260a6fcd096b2b706f9f7bf"),
        "size": 1366,
        "source": None,
    },
    {
        "path": "houses/07-seventh-house.md",
        "sha256": ("57ef2f8000be792ce33be64677cc5267a8c83203e3837a20d53ef46908c79472"),
        "size": 1344,
        "source": None,
    },
    {
        "path": "houses/08-eighth-house.md",
        "sha256": ("445639105eaf4d2a54106cfd04e263122e8eb2a8d1bf0f8bed4eff161497a446"),
        "size": 1737,
        "source": None,
    },
    {
        "path": "houses/09-ninth-house.md",
        "sha256": ("3f5544ab31da28a839ea4ddd1c16ca3f62ca060c1b4b1da3244547ea8e665d7f"),
        "size": 1475,
        "source": None,
    },
    {
        "path": "houses/10-tenth-house.md",
        "sha256": ("b391bc246ab26ebf2361d925db4c9edbb07e96bae2a559fc169c36f60fe3c6d4"),
        "size": 1432,
        "source": None,
    },
    {
        "path": "houses/11-eleventh-house.md",
        "sha256": ("4670d0b6442da70fb3b87277a72b23f2b086af87af54fd2c1aa945cab47f2797"),
        "size": 1521,
        "source": None,
    },
    {
        "path": "houses/12-twelfth-house.md",
        "sha256": ("56fa05fd28f82eb9c7be0868618b5031b605d03f0a7a06935ea7792c1463ccf0"),
        "size": 1654,
        "source": None,
    },
    {
        "path": "references/INTERPRETATION_GUIDE.md",
        "sha256": ("2c359d9ef3c8f7014500b25b57e2f420ae38b93bab6006185c01bbf2afbef548"),
        "size": 7334,
        "source": None,
    },
    {
        "path": "references/TECHNICAL_CONTEXT_LENSES.md",
        "sha256": ("6a2cef145a769eecf30e907d50c53c0445e091c4f3be02fdf73f5d340893fd17"),
        "size": 4722,
        "source": None,
    },
    {
        "path": "scripts/draw_cards.py",
        "sha256": ("4dff224dd219ab0ebbee8453d512c52562df306e5ffd0ec040befc47f7f1f5d9"),
        "size": 9511,
        "source": None,
    },
    {
        "path": "scripts/pyproject.toml",
        "sha256": ("072f982ebfc4397f58891d7c2361e9d3dd8e790c0b6d96bda8b3f472193ddd2f"),
        "size": 144,
        "source": None,
    },
    {
        "path": "scripts/test_draw_cards.py",
        "sha256": ("0fa1854521682215a16240831dac4d84ac1909040f3bbdd198601703d1c9cb24"),
        "size": 14426,
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
