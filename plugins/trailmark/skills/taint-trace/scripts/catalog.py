"""Route to existing analyzers; native probes establish usable analysis scope."""

from typing import TypedDict


class BackendSpec(TypedDict):
    executable: str
    version_args: list[str]


BACKENDS: dict[str, BackendSpec] = {
    "psalm": {"executable": "psalm", "version_args": ["--version"]},
    "pysa": {"executable": "pyre", "version_args": ["--version"]},
    "clang": {"executable": "clang", "version_args": ["--version"]},
    "infer": {"executable": "infer", "version_args": ["--version"]},
    "joern": {"executable": "joern", "version_args": ["--version"]},
    "checker-framework": {"executable": "javac", "version_args": ["-version"]},
    "semgrep": {"executable": "semgrep", "version_args": ["--version"]},
    "semgrep-pro": {"executable": "semgrep", "version_args": ["--version"]},
    "opengrep": {"executable": "opengrep", "version_args": ["--version"]},
    "codeql": {"executable": "codeql", "version_args": ["version"]},
}

LANGUAGES: dict[str, list[str]] = {
    "php": ["psalm", "joern", "semgrep"],
    "python": ["pysa", "joern", "semgrep"],
    "c": ["clang", "infer", "joern", "semgrep"],
    "cpp": ["clang", "infer", "joern", "semgrep"],
    "objc": ["infer", "semgrep"],
    "java": ["joern", "semgrep"],
    "javascript": ["joern", "semgrep"],
    "typescript": ["joern", "semgrep"],
    "kotlin": ["joern", "semgrep"],
    "c_sharp": ["joern", "semgrep"],
    "go": ["joern", "semgrep"],
    "ruby": ["joern", "semgrep"],
    "swift": ["joern", "semgrep"],
    "rust": ["semgrep"],
    "dart": ["semgrep"],
    "bash": ["semgrep"],
    "lua": ["semgrep"],
    "r": ["semgrep"],
    "julia": ["semgrep"],
    "solidity": ["semgrep"],
    "circom": ["semgrep"],
    "move": ["semgrep"],
    "vb": ["opengrep"],
    "powershell": ["semgrep-pro"],
    "cairo": ["semgrep"],
}
CONFIGURED_BACKENDS = {"java": ["infer", "checker-framework"]}

# Restrict the retained, inspected-file inventory to the component language.
# These are Trailmark 0.7 parser suffixes, including templates and module variants.
SOURCE_SUFFIXES = {
    "php": (".php", ".phtml"),
    "python": (".py",),
    "c": (".c",),
    "cpp": (".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx"),
    "objc": (".m", ".mm"),
    "java": (".java",),
    "javascript": (".js", ".jsx", ".mjs", ".cjs"),
    "typescript": (".ts", ".tsx"),
    "kotlin": (".kt", ".kts"),
    "c_sharp": (".cs",),
    "go": (".go",),
    "ruby": (".rb",),
    "swift": (".swift",),
    "rust": (".rs",),
    "dart": (".dart",),
    "bash": (".sh", ".bash"),
    "lua": (".lua",),
    "r": (".r",),
    "julia": (".jl",),
    "solidity": (".sol",),
    "circom": (".circom",),
    "move": (".move",),
    "vb": (".vb",),
    "powershell": (".ps1", ".psm1"),
    "cairo": (".cairo",),
}

CODEQL_LANGUAGES: set[str] = {
    "c",
    "cpp",
    "c_sharp",
    "go",
    "java",
    "kotlin",
    "javascript",
    "typescript",
    "python",
    "ruby",
    "rust",
    "swift",
}
EXPERIMENTAL = {
    "cairo",
    "objc",
    "bash",
    "lua",
    "r",
    "julia",
    "solidity",
    "circom",
    "move",
    "vb",
    "powershell",
}
SCOPES = {
    "intraprocedural",
    "intrafile",
    "interprocedural",
    "translation-unit",
    "cross-translation-unit",
}
ALIASES = {
    "js": "javascript",
    "ts": "typescript",
    "c++": "cpp",
    "c#": "c_sharp",
    "csharp": "c_sharp",
    "objective-c": "objc",
    "objective-c++": "objc",
    "vbnet": "vb",
    "vb.net": "vb",
    "move_on_aptos": "move",
    "move_on_sui": "move",
    "sh": "bash",
    "golang": "go",
}


def canonical_language(language: str) -> str:
    key = language.lower().strip()
    return ALIASES.get(key, key)


def language_source(file: str, language: str, selected: set[str]) -> bool:
    suffix = file[file.rfind(".") :].lower() if "." in file else ""
    if suffix == ".h":
        # Trailmark assigns shared headers once, preferring Objective-C over C.
        owner = "objc" if "objc" in selected else "c" if "c" in selected else None
        return language == owner
    return suffix in SOURCE_SUFFIXES.get(language, ())


def allowed_backend(backend: str, language: str) -> bool:
    language = canonical_language(language)
    if not LANGUAGES.get(language):
        return False
    if backend in {"semgrep-pro", "opengrep"}:
        return language != "powershell" or backend == "semgrep-pro"
    return (
        backend in LANGUAGES[language]
        or backend in CONFIGURED_BACKENDS.get(language, [])
        or (backend == "codeql" and language in CODEQL_LANGUAGES)
    )


def catalog() -> dict:
    return {
        "schema_version": 1,
        "selection": (
            "Existing working taint configuration first; otherwise ordered candidates. "
            "Every selected combination requires a passing native probe."
        ),
        "backends": BACKENDS,
        "languages": {
            name: {
                "candidates": choices,
                "experimental": name in EXPERIMENTAL,
                "configured_backends": CONFIGURED_BACKENDS.get(name, []),
                "optional": ["codeql", "semgrep-pro", "opengrep"]
                if name in CODEQL_LANGUAGES
                else ["semgrep-pro", "opengrep"]
                if choices and name != "powershell"
                else [],
                "reason": "Native taint fixture and target syntax must pass.",
            }
            for name, choices in LANGUAGES.items()
        },
        "unlisted": "Skip languages without both a Trailmark frontend and a native taint backend.",
    }
