"""Small real-analyzer fixtures. These exercise an engine, not application behavior."""

from __future__ import annotations

import json
from pathlib import Path

from catalog import canonical_language

ASSIGNMENTS = {
    "python": (
        "py",
        """def test():
    x = source_input()
    y = x
    sink_output(y)
    sink_output("safe")
    sink_output(sanitize_value(x))
""",
    ),
    "javascript": (
        "js",
        """function test() {
 const x = source_input();
 const y = x;
 sink_output(y);
 sink_output("safe");
 sink_output(sanitize_value(x));
}
""",
    ),
    "typescript": (
        "ts",
        """function test(): void {
 const x = source_input();
 const y = x;
 sink_output(y);
 sink_output("safe");
 sink_output(sanitize_value(x));
}
""",
    ),
    "php": (
        "php",
        """<?php
function test() {
 $x = source_input();
 $y = $x;
 sink_output($y);
 sink_output("safe");
 sink_output(sanitize_value($x));
}
""",
    ),
    "java": (
        "java",
        """class Probe { void test() {
 String x = source_input();
 String y = x;
 sink_output(y);
 sink_output("safe");
 sink_output(sanitize_value(x));
} }
""",
    ),
    "kotlin": (
        "kt",
        """fun test() {
 val x = source_input()
 val y = x
 sink_output(y)
 sink_output("safe")
 sink_output(sanitize_value(x))
}
""",
    ),
    "c_sharp": (
        "cs",
        """class Probe { void Test() {
 var x = source_input();
 var y = x;
 sink_output(y);
 sink_output("safe");
 sink_output(sanitize_value(x));
} }
""",
    ),
    "go": (
        "go",
        """package probe
func test() {
 x := source_input()
 y := x
 sink_output(y)
 sink_output("safe")
 sink_output(sanitize_value(x))
}
""",
    ),
    "ruby": (
        "rb",
        """def test
 x = source_input()
 y = x
 sink_output(y)
 sink_output("safe")
 sink_output(sanitize_value(x))
end
""",
    ),
    "swift": (
        "swift",
        """func test() {
 let x = source_input()
 let y = x
 sink_output(y)
 sink_output("safe")
 sink_output(sanitize_value(x))
}
""",
    ),
    "rust": (
        "rs",
        """fn test() {
 let x = source_input();
 let y = x;
 sink_output(y);
 sink_output("safe");
 sink_output(sanitize_value(x));
}
""",
    ),
    "dart": (
        "dart",
        """void test() {
 var x = source_input();
 var y = x;
 sink_output(y);
 sink_output("safe");
 sink_output(sanitize_value(x));
}
""",
    ),
    "lua": (
        "lua",
        """function test()
 local x = source_input()
 local y = x
 sink_output(y)
 sink_output("safe")
 sink_output(sanitize_value(x))
end
""",
    ),
    "r": (
        "r",
        """test <- function() {
 x <- source_input()
 y <- x
 sink_output(y)
 sink_output("safe")
 sink_output(sanitize_value(x))
}
""",
    ),
    "julia": (
        "jl",
        """function test()
 x = source_input()
 y = x
 sink_output(y)
 sink_output("safe")
 sink_output(sanitize_value(x))
end
""",
    ),
    "solidity": (
        "sol",
        """contract Probe { function test() public {
 string memory x = source_input();
 string memory y = x;
 sink_output(y);
 sink_output("safe");
 sink_output(sanitize_value(x));
} }
""",
    ),
    "circom": (
        "circom",
        """pragma circom 2.0.0;
template Probe() {
 var x = source_input();
 var y = x;
 sink_output(y);
 sink_output(0);
 sink_output(sanitize_value(x));
}
component main = Probe();
""",
    ),
    "move": (
        "move",
        """module 0x1::probe { fun test() {
 let x = source_input();
 let y = x;
 sink_output(y);
 sink_output(0);
 sink_output(sanitize_value(x));
} }
""",
    ),
    "objc": (
        "m",
        """void test() {
 id x = source_input();
 id y = x;
 sink_output(y);
 sink_output(@"safe");
 sink_output(sanitize_value(x));
}
""",
    ),
    "c": (
        "c",
        """void test() {
 char *x = source_input();
 char *y = x;
 sink_output(y);
 sink_output("safe");
 sink_output(sanitize_value(x));
}
""",
    ),
    "cpp": (
        "cpp",
        """void test() {
 auto x = source_input();
 auto y = x;
 sink_output(y);
 sink_output("safe");
 sink_output(sanitize_value(x));
}
""",
    ),
    "bash": (
        "sh",
        """test() {
 x=$(source_input)
 y="$x"
 sink_output "$y"
 sink_output safe
 sink_output "$(sanitize_value "$x")"
}
""",
    ),
    "powershell": (
        "ps1",
        """function Test-Probe {
 $x = source_input
 $y = $x
 sink_output $y
 sink_output "safe"
 sink_output (sanitize_value $x)
}
""",
    ),
    "vb": (
        "vb",
        """Module Probe
Sub Test()
 Dim x As String = source_input()
 Dim y As String = x
 sink_output(y)
 sink_output("safe")
 sink_output(sanitize_value(x))
End Sub
End Module
""",
    ),
}

PSALM_SOURCE = """<?php
/** @psalm-taint-source input */
function request_value(): string { return (string) ($GLOBALS['cms_request']['value'] ?? ''); }
/**
 * @psalm-flow ($value) -> return
 * @psalm-taint-specialize
 */
function wrapper(string $value): string { return $value; }
/**
 * @psalm-taint-escape html
 * @psalm-taint-escape has_quotes
 * @psalm-flow ($value) -> return
 */
function escape_html(string $value): string {
    return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
}
/** @psalm-taint-sink sql $query */
function sql_sink(string $query): void {}
/** @psalm-taint-sink sql $query */
function sql_function_true(string $query): void {}
/** @psalm-taint-sink sql $query */
function sql_function_false(string $query): void {}
/** @psalm-taint-sink sql $query */
function sql_function_unknown(string $query): void {}
/** @psalm-taint-sink sql $query */
function sql_static_true(string $query): void {}
/** @psalm-taint-sink sql $query */
function sql_static_false(string $query): void {}
/** @psalm-taint-sink sql $query */
function sql_static_unknown(string $query): void {}
/** @psalm-taint-sink sql $query */
function sql_instance_true(string $query): void {}
/** @psalm-taint-sink sql $query */
function sql_instance_false(string $query): void {}
/** @psalm-taint-sink sql $query */
function sql_instance_unknown(string $query): void {}
/** @psalm-taint-sink sql $query */
function sql_promoted_field(string $query): void {}
/** @psalm-taint-sink sql $query */
function sql_named_field(string $query): void {}
/** @psalm-taint-sink sql $query */
function sql_named_conditional(string $query): void {}
/** @psalm-taint-sink sql $unsafe */
function named_sql_sink(string $safe, string $unsafe): void {}
/** @psalm-taint-sink sql $unsafe */
function named_sql_negative(string $safe, string $unsafe): void {}
/**
 * @psalm-flow ($unsafe) -> return
 * @psalm-taint-specialize
 */
function named_relay(string $safe, string $unsafe): string { return $unsafe; }
/**
 * @psalm-flow ($value) -> return
 * @psalm-taint-escape ($escape is true ? 'html' : null)
 * @psalm-taint-escape ($escape is true ? 'has_quotes' : null)
 * @psalm-taint-specialize
 */
function conditional_html(string $value, bool $escape): string {
    return $escape ? htmlspecialchars($value, ENT_QUOTES, 'UTF-8') : $value;
}
final class ConditionalEscaper {
    /**
     * @psalm-flow ($value) -> return
     * @psalm-taint-escape ($escape is true ? 'html' : null)
     * @psalm-taint-escape ($escape is true ? 'has_quotes' : null)
     * @psalm-taint-specialize
     */
    public static function escape_static(string $value, bool $escape): string {
        return $escape ? htmlspecialchars($value, ENT_QUOTES, 'UTF-8') : $value;
    }
    /**
     * @psalm-flow ($value) -> return
     * @psalm-taint-escape ($escape is true ? 'html' : null)
     * @psalm-taint-escape ($escape is true ? 'has_quotes' : null)
     * @psalm-taint-specialize
     * @psalm-pure
     */
    public function escape_instance(string $value, bool $escape): string {
        return $escape ? htmlspecialchars($value, ENT_QUOTES, 'UTF-8') : $value;
    }
}
final class PromotedPair {
    public function __construct(private readonly string $unsafe, private readonly string $safe) {}
    public function unsafe_value(): string { return $this->unsafe; }
    public function safe_value(): string { return $this->safe; }
    public function constant_value(): string { return 'literal-constant'; }
}
final class NamedPromotedPair {
    public function __construct(private readonly string $unsafe, private readonly string $safe) {}
    public function unsafe_value(): string { return $this->unsafe; }
    public function safe_value(): string { return $this->safe; }
    public function constant_value(): string { return 'literal-constant'; }
}
exec(wrapper(request_value()));
exec('literal-safe-command');
echo request_value();
echo escape_html(request_value());
sql_sink(escape_html(request_value()));
$unknown = (bool) ($GLOBALS['escape'] ?? false);
echo conditional_html(request_value(), true);
echo conditional_html(request_value(), false);
echo conditional_html(request_value(), $unknown);
echo conditional_html('literal-safe-value', false);
sql_function_true(conditional_html(request_value(), true));
sql_function_false(conditional_html(request_value(), false));
sql_function_unknown(conditional_html(request_value(), $unknown));
echo ConditionalEscaper::escape_static(request_value(), true);
echo ConditionalEscaper::escape_static(request_value(), false);
echo ConditionalEscaper::escape_static(request_value(), $unknown);
echo ConditionalEscaper::escape_static('literal-safe-value', false);
sql_static_true(ConditionalEscaper::escape_static(request_value(), true));
sql_static_false(ConditionalEscaper::escape_static(request_value(), false));
sql_static_unknown(ConditionalEscaper::escape_static(request_value(), $unknown));
$escaper = new ConditionalEscaper();
echo $escaper->escape_instance(request_value(), true);
echo $escaper->escape_instance(request_value(), false);
echo $escaper->escape_instance(request_value(), $unknown);
echo $escaper->escape_instance('literal-safe-value', false);
sql_instance_true($escaper->escape_instance(request_value(), true));
sql_instance_false($escaper->escape_instance(request_value(), false));
sql_instance_unknown($escaper->escape_instance(request_value(), $unknown));
$pair = new PromotedPair(request_value(), 'literal-field');
echo $pair->unsafe_value();
echo $pair->safe_value();
echo $pair->constant_value();
sql_promoted_field($pair->unsafe_value());
$named = new NamedPromotedPair(safe: 'literal-field', unsafe: request_value());
echo $named->unsafe_value();
echo $named->safe_value();
echo $named->constant_value();
sql_named_field($named->unsafe_value());
echo named_relay(unsafe: request_value(), safe: 'literal');
echo named_relay(unsafe: 'literal', safe: request_value());
named_sql_sink(unsafe: request_value(), safe: 'literal');
named_sql_negative(unsafe: 'literal', safe: request_value());
echo conditional_html(escape: true, value: request_value());
echo conditional_html(escape: false, value: request_value());
sql_named_conditional(conditional_html(escape: true, value: request_value()));
"""


def sites(source: str, filename: str, needles: list[str]) -> list[dict]:
    result = []
    for needle in needles:
        lines = [i for i, line in enumerate(source.splitlines(), 1) if needle in line]
        if len(lines) != 1:
            raise ValueError(f"Fixture anchor {needle!r} is not unique")
        result.append({"file": filename, "line": lines[0]})
    return result


def semgrep_patterns(canonical: str) -> list[str]:
    if canonical in {"bash", "powershell"}:
        return ["source_input", "sink_output $X", "sanitize_value $X"]
    return ["source_input(...)", "sink_output(...)", "sanitize_value(...)"]


def semgrep_anchors(canonical: str) -> tuple[str, str, str]:
    special = {
        "bash": ('sink_output "$y"', "sink_output safe", 'sink_output "$(sanitize_value'),
        "powershell": ("sink_output $y", 'sink_output "safe"', "sink_output (sanitize_value"),
    }
    if canonical in special:
        return special[canonical]
    positive = "sink_output($y)" if canonical == "php" else "sink_output(y)"
    negative = {
        "objc": 'sink_output(@"safe")',
        "move": "sink_output(0)",
        "circom": "sink_output(0)",
    }.get(canonical, 'sink_output("safe")')
    return positive, negative, "sink_output(sanitize_value"


def semgrep_rule(language: str, canonical: str) -> dict:
    rule_language = {"c_sharp": "csharp", "move": "move_on_aptos"}.get(canonical, canonical)
    if language == "move_on_sui":
        rule_language = language
    patterns = semgrep_patterns(canonical)
    return {
        "rules": [
            {
                "id": "taint-trace-capability",
                "languages": [rule_language],
                "mode": "taint",
                "message": "Native engine capability fixture",
                "severity": "WARNING",
                "pattern-sources": [{"pattern": patterns[0]}],
                "pattern-sinks": [{"pattern": patterns[1]}],
                "pattern-sanitizers": [{"pattern": patterns[2]}],
            }
        ]
    }


def semgrep_fixture(root: Path, language: str) -> dict:
    canonical = canonical_language(language)
    ext, source = ASSIGNMENTS[canonical]
    if language == "move_on_sui":
        source = source.replace("module 0x1::probe", "module probe::probe")
    name = f"probe.{ext}"
    (root / name).write_text(source, encoding="utf-8")
    (root / "rule.json").write_text(
        json.dumps(semgrep_rule(language, canonical), indent=2) + "\n", encoding="utf-8"
    )
    positive, negative, sanitizer = semgrep_anchors(canonical)
    return {
        "file": name,
        "scope": "intraprocedural",
        "expect": {
            "positive": sites(source, name, [positive]),
            "negative": sites(source, name, [negative, sanitizer]),
        },
    }


def psalm_typed_sites(needles: list[str]) -> list[dict]:
    return [{**site, "rule_id": "TaintedSql"} for site in sites(PSALM_SOURCE, "probe.php", needles)]


def psalm_core_expectations() -> dict:
    return {
        "positive": sites(PSALM_SOURCE, "probe.php", ["exec(wrapper", "echo request_value"])
        + psalm_typed_sites(["function sql_sink("]),
        "negative": sites(PSALM_SOURCE, "probe.php", ["exec('literal", "echo escape_html"]),
        "cross_function": sites(PSALM_SOURCE, "probe.php", ["exec(wrapper"]),
    }


def conditional_expectations(kind: str) -> dict:
    calls = {
        "function": "conditional_html",
        "static": "ConditionalEscaper::escape_static",
        "instance": "$escaper->escape_instance",
    }
    call = calls[kind]
    return {
        "positive": sites(
            PSALM_SOURCE,
            "probe.php",
            [
                f"echo {call}(request_value(), false)",
                f"echo {call}(request_value(), $unknown)",
            ],
        )
        + psalm_typed_sites(
            [
                f"function sql_{kind}_true(",
                f"function sql_{kind}_false(",
                f"function sql_{kind}_unknown(",
            ]
        ),
        "negative": sites(
            PSALM_SOURCE,
            "probe.php",
            [
                f"echo {call}(request_value(), true)",
                f"echo {call}('literal",
            ],
        ),
    }


def promoted_expectations() -> dict:
    return {
        "positive": sites(PSALM_SOURCE, "probe.php", ["echo $pair->unsafe_value()"])
        + psalm_typed_sites(["function sql_promoted_field("]),
        "negative": sites(
            PSALM_SOURCE,
            "probe.php",
            [
                "echo $pair->safe_value()",
                "echo $pair->constant_value()",
            ],
        ),
    }


def named_expectations() -> dict:
    return {
        "positive": sites(
            PSALM_SOURCE,
            "probe.php",
            [
                "echo $named->unsafe_value()",
                "echo named_relay(unsafe: request_value()",
                "echo conditional_html(escape: false",
            ],
        )
        + psalm_typed_sites(
            [
                "function sql_named_field(",
                "function sql_named_conditional(",
                "function named_sql_sink(",
            ]
        ),
        "negative": sites(
            PSALM_SOURCE,
            "probe.php",
            [
                "echo $named->safe_value()",
                "echo $named->constant_value()",
                "echo named_relay(unsafe: 'literal'",
                "echo conditional_html(escape: true",
            ],
        )
        + psalm_typed_sites(["function named_sql_negative("]),
    }


def psalm_optional_expectations() -> dict:
    return {
        **{
            f"conditional_{kind}": conditional_expectations(kind)
            for kind in ("function", "static", "instance")
        },
        "promoted_fields": promoted_expectations(),
        "named_bindings": named_expectations(),
    }


def psalm_fixture(root: Path) -> dict:
    (root / "probe.php").write_text(PSALM_SOURCE, encoding="utf-8")
    baseline = root / "unmodeled"
    baseline.mkdir()
    (baseline / "probe.php").write_text(
        PSALM_SOURCE.replace("/** @psalm-taint-source input */\n", ""), encoding="utf-8"
    )
    config = (
        '<?xml version="1.0"?><psalm errorLevel="1" resolveFromConfigFile="true" '
        'xmlns="https://getpsalm.org/schema/config"><projectFiles><file name="probe.php"/>'
        "</projectFiles></psalm>\n"
    )
    (root / "psalm.xml").write_text(config, encoding="utf-8")
    (root / "psalm-baseline.xml").write_text(
        config.replace('name="probe.php"', 'name="unmodeled/probe.php"'), encoding="utf-8"
    )
    return {
        "file": "probe.php",
        "scope": "interprocedural",
        "baseline_config": "psalm-baseline.xml",
        "expect": psalm_core_expectations(),
        "optional_expect": psalm_optional_expectations(),
    }
