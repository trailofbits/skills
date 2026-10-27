"""Emit executable Joern capability fixtures; Joern alone computes every flow."""

# Native fixture statements retain one-line sink locations across frontends.
# ruff: noqa: E501

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from typing import Any

from catalog import canonical_language

C_SOURCE = """/* html_escape is a pure HTML-only external escaping contract. */
extern char *request_value(void);
extern void html_output(const char *value);
extern void sql_execute(const char *value);
extern char *html_escape(const char *value);
static const char *relay_value(const char *value) { return value; }
void direct(void) { html_output(request_value()); }
void literal(void) { html_output("literal"); }
void sanitized(void) { html_output(html_escape(request_value())); }
void other_context(void) { sql_execute(html_escape(request_value())); }
void ignored_return(void) { char *value = request_value(); html_escape(value); html_output(value); }
void cross_function(void) { html_output(relay_value(request_value())); }
void alias(void) { char *value = request_value(); char *copy = value; html_output(copy); }
"""

JAVA_SOURCE = """class Probe {
  static String request_value() { return System.getenv("INPUT"); }
  static native void html_output(String value);
  static native void sql_execute(String value);
  // Pure HTML-only external escaping contract.
  static native String html_escape(String value);
  static String relay_value(String value) { return value; }
  static void direct() { html_output(request_value()); }
  static void literal() { html_output("literal"); }
  static void sanitized() { html_output(html_escape(request_value())); }
  static void other_context() { sql_execute(html_escape(request_value())); }
  static void ignored_return() { String value = request_value(); html_escape(value); html_output(value); }
  static void cross_function() { html_output(relay_value(request_value())); }
  static void alias() { String value = request_value(); String copy = value; html_output(copy); }
}
"""

PYTHON_SOURCE = """from html import escape
def request_value():
    return input()
def html_output(value):
    print(value)
def sql_execute(value):
    pass
def html_escape(value):
    return escape(value, quote=True)
def relay_value(value):
    return value
def direct():
    html_output(request_value())
def literal():
    html_output("literal")
def sanitized():
    html_output(html_escape(request_value()))
def other_context():
    sql_execute(html_escape(request_value()))
def ignored_return():
    value = request_value()
    html_escape(value)
    html_output(value)
def cross_function():
    html_output(relay_value(request_value()))
def alias():
    value = request_value()
    copy = value
    html_output(copy)
"""

JAVASCRIPT_SOURCE = """function request_value() { return process.env.INPUT; }
function html_output(value) { console.log(value); }
function sql_execute(value) { console.log(value); }
function html_escape(value) { return value.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#39;'); }
function relay_value(value) { return value; }
function direct() { html_output(request_value()); }
function literal() { html_output("literal"); }
function sanitized() { html_output(html_escape(request_value())); }
function other_context() { sql_execute(html_escape(request_value())); }
function ignored_return() { const value = request_value(); html_escape(value); html_output(value); }
function cross_function() { html_output(relay_value(request_value())); }
function alias() { const value = request_value(); const copy = value; html_output(copy); }
"""

PHP_SOURCE = """<?php
function request_value(): string { return $_GET['value']; }
function html_output(string $value): void { echo $value; }
function sql_execute(string $value): void { echo $value; }
function html_escape(string $value): string { return htmlspecialchars($value, ENT_QUOTES, 'UTF-8'); }
function relay_value(string $value): string { return $value; }
function direct(): void { html_output(request_value()); }
function literal(): void { html_output("literal"); }
function sanitized(): void { html_output(html_escape(request_value())); }
function other_context(): void { sql_execute(html_escape(request_value())); }
function ignored_return(): void { $value = request_value(); html_escape($value); html_output($value); }
function cross_function(): void { html_output(relay_value(request_value())); }
function alias(): void { $value = request_value(); $copy = $value; html_output($copy); }
"""

RUBY_SOURCE = """require 'cgi'
def request_value(); ENV['INPUT']; end
def html_output(value); puts(value); end
def sql_execute(value); puts(value); end
def html_escape(value); CGI.escapeHTML(value); end
def relay_value(value); value; end
def direct(); html_output(request_value()); end
def literal(); html_output("literal"); end
def sanitized(); html_output(html_escape(request_value())); end
def other_context(); sql_execute(html_escape(request_value())); end
def ignored_return(); value = request_value(); html_escape(value); html_output(value); end
def cross_function(); html_output(relay_value(request_value())); end
def alias(); value = request_value(); copy = value; html_output(copy); end
"""

GO_SOURCE = """package probe
import ("html"; "os")
func request_value() string { return os.Getenv("INPUT") }
func html_output(value string) { println(value) }
func sql_execute(value string) { println(value) }
func html_escape(value string) string { return html.EscapeString(value) }
func relay_value(value string) string { return value }
func direct() { html_output(request_value()) }
func literal() { html_output("literal") }
func sanitized() { html_output(html_escape(request_value())) }
func other_context() { sql_execute(html_escape(request_value())) }
func ignored_return() { value := request_value(); html_escape(value); html_output(value) }
func cross_function() { html_output(relay_value(request_value())) }
func alias() { value := request_value(); copy := value; html_output(copy) }
"""

CSHARP_SOURCE = """class Probe {
  static string request_value() { return System.Environment.GetEnvironmentVariable("INPUT"); }
  static void html_output(string value) { System.Console.WriteLine(value); }
  static void sql_execute(string value) { System.Console.WriteLine(value); }
  static string html_escape(string value) { return System.Net.WebUtility.HtmlEncode(value); }
  static string relay_value(string value) { return value; }
  static void direct() { html_output(request_value()); }
  static void literal() { html_output("literal"); }
  static void sanitized() { html_output(html_escape(request_value())); }
  static void other_context() { sql_execute(html_escape(request_value())); }
  static void ignored_return() { string value = request_value(); html_escape(value); html_output(value); }
  static void cross_function() { html_output(relay_value(request_value())); }
  static void alias() { string value = request_value(); string copy = value; html_output(copy); }
}
"""

KOTLIN_SOURCE = """fun request_value(): String { return System.getenv("INPUT") }
fun html_output(value: String) { println(value) }
fun sql_execute(value: String) { println(value) }
fun html_escape(value: String): String { return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\\\"", "&quot;").replace("'", "&#39;") }
fun relay_value(value: String): String { return value }
fun direct() { html_output(request_value()) }
fun literal() { html_output("literal") }
fun sanitized() { html_output(html_escape(request_value())) }
fun other_context() { sql_execute(html_escape(request_value())) }
fun ignored_return() { val value = request_value(); html_escape(value); html_output(value) }
fun cross_function() { html_output(relay_value(request_value())) }
fun alias() { val value = request_value(); val copy = value; html_output(copy) }
"""

SWIFT_SOURCE = """import Foundation
func request_value() -> String { return readLine()! }
func html_output(_ value: String) { print(value) }
func sql_execute(_ value: String) { print(value) }
func html_escape(_ value: String) -> String { return value.replacingOccurrences(of: "&", with: "&amp;").replacingOccurrences(of: "<", with: "&lt;").replacingOccurrences(of: ">", with: "&gt;").replacingOccurrences(of: "\\\"", with: "&quot;").replacingOccurrences(of: "'", with: "&#39;") }
func relay_value(_ value: String) -> String { return value }
func direct() { html_output(request_value()) }
func literal() { html_output("literal") }
func sanitized() { html_output(html_escape(request_value())) }
func other_context() { sql_execute(html_escape(request_value())) }
func ignored_return() { let value = request_value(); _ = html_escape(value); html_output(value) }
func cross_function() { html_output(relay_value(request_value())) }
func alias() { let value = request_value(); let copy = value; html_output(copy) }
"""

# Frontend identifiers are native joern-parse language IDs, not Trailmark aliases.
FIXTURES = {
    "c": ("probe.c", "C", C_SOURCE),
    "cpp": ("probe.cpp", "C", C_SOURCE),
    "java": ("Probe.java", "JAVASRC", JAVA_SOURCE),
    "python": ("probe.py", "PYTHONSRC", PYTHON_SOURCE),
    "javascript": ("probe.js", "JSSRC", JAVASCRIPT_SOURCE),
    "typescript": ("probe.ts", "JSSRC", JAVASCRIPT_SOURCE),
    "php": ("probe.php", "PHP", PHP_SOURCE),
    "ruby": ("probe.rb", "RUBYSRC", RUBY_SOURCE),
    "go": ("probe.go", "GOLANG", GO_SOURCE),
    "c_sharp": ("Probe.cs", "CSHARPSRC", CSHARP_SOURCE),
    "kotlin": ("Probe.kt", "KOTLIN", KOTLIN_SOURCE),
    "swift": ("probe.swift", "SWIFTSRC", SWIFT_SOURCE),
}

QUERY = r"""import io.joern.dataflowengineoss.DefaultSemantics
import io.joern.dataflowengineoss.language.*
import io.joern.dataflowengineoss.queryengine.EngineContext
import io.joern.dataflowengineoss.semanticsloader.FlowSemantic
import io.shiftleft.semanticcpg.language.*

@main def exec(cpgFile: String, outFile: String) = {
  val findings = scala.collection.mutable.ListBuffer.empty[ujson.Value]
  val scanned = scala.collection.mutable.Set.empty[String]
  for (context <- List("html", "sql")) {
    // Each policy imports the original CPG into a separate project.
    // SQL retains input-to-return flow: HTML escaping is not SQL sanitization.
    val loaded = importCpg(cpgFile, projectName = "trailmark-" + context)
    require(loaded.nonEmpty, "CPG import failed")
    val sourceRoot = java.nio.file.Path.of(cpg.metaData.root.head)
    // CSHARPSRC preserves Roslyn's zero-based lines. Retain native_line
    // and export the one-based locations required by the common artifact format.
    val lineOffset = if (cpg.metaData.language.head == "CSHARPSRC") 1 else 0
    def sourceFile(name: String): String = {
      if (name.isEmpty || name.startsWith("<")) name
      else sourceRoot.resolve(name).toAbsolutePath.normalize.toString
    }
    val cleanerNames = cpg.call.nameExact("html_escape").callee.fullName.toList.distinct
    require(cleanerNames.nonEmpty && cleanerNames.forall(!_.startsWith("<")),
      "Sanitizer call has no resolved native callee")
    val mappings = if (context == "html") List((0, 0), (1, 1))
                   else List((0, 0), (1, 1), (1, -1))
    val policy = DefaultSemantics().plus(cleanerNames.map(FlowSemantic.from(_, mappings)))
    val sources = cpg.call.nameExact("request_value").toList
    val sinkName = if (context == "html") "html_output" else "sql_execute"
    val sinks = cpg.call.nameExact(sinkName).argument(1).toList
    require(sources.nonEmpty && sinks.nonEmpty, "Empty source or sink query")
    val paths = sinks.iterator.reachableByFlows(sources)(EngineContext(policy)).toList
    paths.iterator.p #> (outFile + "." + context + ".txt")
    // These are frontend-created FILE nodes for unknown/external/global code.
    // Other missing paths fail instead of silently disappearing from coverage.
    val files = cpg.file.name.filterNot(name =>
      name.startsWith("<") || Set("N/A", "/", "builtintypes").contains(name))
      .map(sourceFile).toList.distinct
    require(files.nonEmpty, "No source files in CPG")
    require(files.forall(name => java.nio.file.Files.isRegularFile(java.nio.file.Path.of(name))),
      "CPG inventory contains missing source files")
    scanned ++= files
    for (path <- paths) {
      val sink = path.elements.last
      require(sink.lineNumber.exists(_ + lineOffset > 0), "Sink has no source line")
      val sinkFile = sourceFile(sink.file.name.headOption.getOrElse(""))
      require(sinkFile.nonEmpty && !sinkFile.startsWith("<"), "Sink has no source file")
      findings += ujson.Obj(
        "rule_id" -> ("trailmark.request-to-" + context),
        "file" -> sinkFile, "line" -> (sink.lineNumber.get + lineOffset),
        "native_line" -> sink.lineNumber.get,
        "message" -> ("Request data reaches " + context + " sink"),
        "trace" -> ujson.Arr.from(path.elements.map { node =>
          ujson.Obj("file" -> sourceFile(node.file.name.headOption.getOrElse("")),
            "line" -> node.lineNumber.map(_ + lineOffset).getOrElse(0),
            "native_line" -> node.lineNumber.getOrElse(-1), "code" -> node.code,
            "method" -> node.start.inAst.isMethod.fullName.headOption.getOrElse(""))
        }))
    }
    close
  }
  val report = ujson.Obj("tool" -> "joern",
    "findings" -> ujson.Arr.from(findings),
    "scanned_files" -> ujson.Arr.from(scanned.toList.sorted), "errors" -> ujson.Arr())
  java.nio.file.Files.writeString(java.nio.file.Path.of(outFile), ujson.write(report))
}
"""


def fixture_site(source: str, file: str, needle: str) -> dict[str, Any]:
    matches = [i for i, line in enumerate(source.splitlines(), 1) if needle in line]
    if len(matches) != 1:
        raise ValueError(f"Fixture marker must match exactly once: {needle}")
    return {"file": f"source/{file}", "line": matches[0]}


def fixture_expectations(source: str, file: str, language: str) -> dict[str, Any]:
    def site(needle: str) -> dict[str, Any]:
        return fixture_site(source, file, needle)

    positive = [
        site("html_output(request_value())"),
        site("sql_execute(html_escape(request_value()))"),
        site("html_output(relay_value(request_value()))"),
    ]
    extra = (
        ["    html_output(value)", "    html_output(copy)"]
        if language == "python"
        else [
            "void ignored_return" if language == "java" else "ignored_return(",
            "void alias" if language == "java" else "alias(",
        ]
    )
    return {
        "positive": positive + [site(marker) for marker in extra],
        "negative": [
            site('html_output("literal")'),
            site("html_output(html_escape(request_value()))"),
        ],
        "cross_function": [site("html_output(relay_value(request_value()))")],
    }


def joern_commands(root: Path, executable: str, frontend: str) -> list[list[str]]:
    resolved = shutil.which(executable)
    binary = Path(resolved or executable).resolve() if resolved else Path(executable)
    return [
        [
            str(binary.with_name("joern-parse")),
            str((root / "source").resolve()),
            "--language",
            frontend,
            "--output",
            str((root / "cpg.bin").resolve()),
        ],
        [
            str(binary),
            "--script",
            str((root / "trace.sc").resolve()),
            "--param",
            f"cpgFile={(root / 'cpg.bin').resolve()}",
            "--param",
            f"outFile={(root / 'joern.json').resolve()}",
        ],
    ]


def joern_fixture(root: Path, language: str, executable: str = "joern") -> dict[str, Any]:
    """Write a language fixture and return native parse/query argv and assertions."""
    language = canonical_language(language)
    if language not in FIXTURES:
        raise ValueError(f"Joern has no built-in native capability fixture for {language}")
    file, frontend, source = FIXTURES[language]
    source_root = root / "source"
    source_root.mkdir(parents=True, exist_ok=True)
    (source_root / file).write_text(source, encoding="utf-8")
    if language == "go":
        (source_root / "go.mod").write_text("module trailmark-probe\n\ngo 1.23\n", encoding="utf-8")
    (root / "trace.sc").write_text(QUERY, encoding="utf-8")
    commands = joern_commands(root, executable, frontend)
    return {
        "backend": "joern",
        "language": language,
        "scope": "interprocedural",
        "expect": fixture_expectations(source, file, language),
        "commands": commands,
        "native_output": str((root / "joern.json").resolve()),
        "version_command": [commands[1][0], "--version"],
    }


def write_contract(directory: Path, language: str, executable: str = "joern") -> Path:
    """Create a standalone contract that the common native probe can consume."""
    directory = directory.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    fixture_root = directory / "fixture"
    fixture = joern_fixture(fixture_root, language, executable)
    # Capability contracts copy source into a persistent workdir before running.
    fixture["fixture_root"] = "fixture"
    fixture["commands"] = [
        [arg.replace(str(fixture_root), "{workdir}") for arg in command]
        for command in fixture["commands"]
    ]
    fixture["native_output"] = "{workdir}/joern.json"
    contract = directory / "contract.json"
    contract.write_text(json.dumps(fixture, indent=2) + "\n", encoding="utf-8")
    return contract


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--language", required=True, choices=sorted(FIXTURES))
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--executable", default="joern")
    args = parser.parse_args()
    print(write_contract(args.output, args.language, args.executable))


if __name__ == "__main__":
    main()
