"""Small native contracts for the modeling mechanisms introduced by Psalm 7."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from textwrap import dedent


@dataclass(frozen=True)
class Feature:
    source: str
    models: str = ""
    configuration: str = ""


# Markers name the native issue required at that exact source location. A negative
# marker without a rule rejects every taint issue, rather than just one threat.
FEATURES = {
    "conditional_sinks": Feature(
        """\
        <?php
        render_raw((string) $_GET['input'], 1); // positive:TaintedHtml
        render_safe((string) $_GET['input'], 0); // negative
        render_literal('literal', 1); // negative
        """,
        """\
        <?php
        /** @psalm-taint-sink ($mode is 0 ? null : 'html') $content */
        function render_raw(string $content, int $mode): void {}
        /** @psalm-taint-sink ($mode is 0 ? null : 'html') $content */
        function render_safe(string $content, int $mode): void {}
        /** @psalm-taint-sink ($mode is 0 ? null : 'html') $content */
        function render_literal(string $content, int $mode): void {}
        """,
    ),
    "array_value_sinks": Feature(
        """\
        <?php
        values_sink(['key' => (string) $_GET['input']]); // positive:TaintedSql
        keys_control([(string) $_GET['input'] => 'literal']); // negative
        literal_control(['key' => 'literal']); // negative
        """,
        """\
        <?php
        /**
         * @param array<string, string> $values
         * @psalm-taint-sink sql $values[*]
         */
        function values_sink(array $values): void {}
        /**
         * @param array<string, string> $values
         * @psalm-taint-sink sql $values[*]
         */
        function keys_control(array $values): void {}
        /**
         * @param array<string, string> $values
         * @psalm-taint-sink sql $values[*]
         */
        function literal_control(array $values): void {}
        """,
    ),
    "keyed_return_sources": Feature(
        """\
        <?php
        $data = payload();
        echo $data['unsafe']; // positive:TaintedHtml
        echo $data['safe']; // negative
        echo 'literal'; // negative
        """,
        """\
        <?php
        /**
         * @return array{unsafe: string, safe: string}
         * @psalm-taint-source input return['unsafe']
         */
        function payload(): array {}
        """,
    ),
    "taint_complements": Feature(
        """\
        <?php
        $value = complement_source();
        echo $value; // positive:TaintedHtml
        header($value); // negative:TaintedHeader
        echo 'literal'; // negative
        """,
        """\
        <?php
        /** @psalm-taint-source ~(header|user_secret|system_secret) */
        function complement_source(): string {}
        """,
    ),
    "callable_flows": Feature(
        """\
        <?php
        echo compute(fn(): string => (string) $_GET['input']); // positive:TaintedHtml
        echo compute(fn(): string => 'literal'); // negative
        """,
        """\
        <?php
        /**
         * @param callable(): string $compute
         * @psalm-taint-specialize
         * @psalm-flow ($compute()) -> return
         */
        function compute(callable $compute): string {}
        """,
    ),
    "receiver_flows": Feature(
        """\
        <?php
        echo fetch_message()->body(); // positive:TaintedHtml
        echo clean_message()->body(); // negative
        """,
        """\
        <?php
        interface Message {
            /**
             * @psalm-taint-specialize
             * @psalm-flow ($this) -> return
             */
            public function body(): string;
        }
        /** @psalm-taint-source input */
        function fetch_message(): Message {}
        function clean_message(): Message {}
        """,
    ),
    "property_flows": Feature(
        """\
        <?php
        function exercise(Request $request): void {
            $request->set('unsafe', (string) $_GET['input']);
            $request->set('safe', 'literal');
            echo $request->get('unsafe'); // positive:TaintedHtml
            echo $request->get('safe'); // negative
            echo $request->get('other'); // negative
        }
        """,
        """\
        <?php
        abstract class Request {
            /** @var array<string, string> */
            protected array $values = [];
            /** @psalm-flow ($value) -> $this->values[$name] */
            abstract public function set(string $name, string $value): void;
            /** @psalm-flow $this->values[$name] -> return */
            abstract public function get(string $name): string;
        }
        """,
    ),
    "named_property_flows": Feature(
        """\
        <?php
        function exercise(Model $model): void {
            $model->set('unsafe', (string) $_GET['input']);
            $model->set('safe', 'literal');
            echo $model->get('unsafe'); // positive:TaintedHtml
            echo $model->get('safe'); // negative
        }
        """,
        """\
        <?php
        abstract class Model {
            public string $unsafe = '';
            public string $safe = '';
            /** @psalm-flow ($value) -> $this->$name */
            abstract public function set(string $name, string $value): void;
            /** @psalm-flow $this->$name -> return */
            abstract public function get(string $name): string;
        }
        """,
    ),
    "keyed_store_flows": Feature(
        """\
        <?php
        Store::set('unsafe', (string) $_GET['input']);
        Store::set('safe', 'literal');
        echo Store::get('unsafe'); // positive:TaintedHtml
        echo Store::get('safe'); // negative
        echo Store::get('other'); // negative
        """,
        """\
        <?php
        final class Store {
            /** @psalm-flow ($value) -> Store::$data[$key] */
            public static function set(string $key, string $value): void {}
            /** @psalm-flow Store::$data[$key] -> return */
            public static function get(string $key): string {}
        }
        """,
    ),
    "property_bags": Feature(
        """\
        <?php
        /**
         * @property string $unsafe
         * @property string $safe
         * @psalm-taint-property-bag $properties
         */
        final class Article {
            /** @var array<string, string> */
            protected array $properties = [];
            public function setUnsafe(string $value): void {
                $this->properties['unsafe'] = $value;
            }
            public function __get(string $name): string {
                return $this->properties[$name] ?? '';
            }
        }
        function exercise(Article $article): void {
            $article->setUnsafe((string) $_GET['input']);
            echo $article->unsafe; // positive:TaintedHtml
            echo $article->safe; // negative
        }
        """,
    ),
    "custom_taints": Feature(
        """\
        <?php
        custom_sink(custom_source()); // positive:TaintedCustom
        custom_literal('literal'); // negative
        echo custom_source(); // negative:TaintedHtml
        """,
        """\
        <?php
        /** @psalm-taint-source project_secret */
        function custom_source(): string {}
        /** @psalm-taint-sink project_secret $value */
        function custom_sink(string $value): void {}
        /** @psalm-taint-sink project_secret $value */
        function custom_literal(string $value): void {}
        """,
        '<taintAnalysis><taints><taint name="project_secret"/></taints></taintAnalysis>',
    ),
    "cli_output": Feature(
        """\
        <?php
        /** @psalm-cli-only */
        function command(): void {
            echo (string) $_GET['input']; // negative:TaintedHtml
            exec((string) $_GET['input']); // positive:TaintedShell
        }
        function web(): void {
            echo (string) $_GET['input']; // positive:TaintedHtml
            echo 'literal'; // negative
        }
        """,
    ),
    "capabilities": Feature(
        """\
        <?php
        /** @psalm-pure */
        function invalid(): string { output(); return 'literal'; } // diagnostic:ImpureFunctionCall
        /** @psalm-pure */
        function valid(): string { return identity('literal'); } // no-diagnostic:ImpureFunctionCall
        echo identity((string) $_GET['input']); // positive:TaintedHtml
        echo identity('literal'); // negative
        """,
        """\
        <?php
        /**
         * @psalm-capabilities pure
         * @psalm-flow ($value) -> return
         * @psalm-taint-specialize
         */
        function identity(string $value): string {}
        /** @psalm-capabilities io */
        function output(): void {}
        """,
    ),
    "purity_templates": Feature(
        """\
        <?php
        /**
         * @psalm-pure
         * @param Closure[_](string): string $compute
         */
        function apply(Closure $compute, string $value): string { return $compute($value); }
        /** @psalm-pure */
        function invalid(): string {
            return apply( // diagnostic:ImpureFunctionCall
                function(string $value): string { echo $value; return $value; },
                'literal'
            );
        }
        /** @psalm-pure */
        function valid(): string {
            return apply( // no-diagnostic:ImpureFunctionCall
                fn(string $value): string => $value, 'literal'
            );
        }
        echo apply( // positive:TaintedHtml
            fn(string $value): string => $value, (string) $_GET['input']
        );
        echo apply(fn(string $value): string => $value, 'literal'); // negative
        """,
    ),
    "automatic_specialization": Feature(
        """\
        <?php
        function identity(string $value): string { return $value; }
        echo identity((string) $_GET['input']); // positive:TaintedHtml
        echo identity('literal'); // negative
        """,
    ),
}


def feature_files(name: str) -> dict[str, str]:
    feature = FEATURES[name]
    files = {"probe.php": dedent(feature.source)}
    stubs = ""
    if feature.models:
        files["models.phpstub"] = dedent(feature.models)
        stubs = '<stubs><file name="models.phpstub"/></stubs>'
    files["psalm.xml"] = (
        '<?xml version="1.0"?><psalm errorLevel="1" resolveFromConfigFile="true" '
        'findUnusedCode="false" xmlns="https://getpsalm.org/schema/config">'
        '<projectFiles><file name="probe.php"/></projectFiles>'
        + stubs
        + feature.configuration
        + "</psalm>\n"
    )
    return files


def marked_sites(name: str, marker: str) -> list[dict]:
    result = []
    for filename, source in feature_files(name).items():
        for number, line in enumerate(source.splitlines(), 1):
            suffix = line.partition("// " + marker)[2]
            if not suffix and not line.rstrip().endswith("// " + marker):
                continue
            site = {"file": filename, "line": number}
            if suffix.startswith(":"):
                site["rule_id"] = suffix[1:].strip()
            result.append(site)
    return result


def feature_expectations(name: str) -> dict:
    return {key: marked_sites(name, key) for key in ("positive", "negative")}


def diagnostic_expectations(name: str) -> dict:
    return {
        "positive": marked_sites(name, "diagnostic"),
        "negative": marked_sites(name, "no-diagnostic"),
    }


def write_feature(root: Path, name: str) -> list[Path]:
    root.mkdir(parents=True)
    files = []
    for filename, source in feature_files(name).items():
        path = root / filename
        path.write_text(source, encoding="utf-8")
        files.append(path)
    return files
