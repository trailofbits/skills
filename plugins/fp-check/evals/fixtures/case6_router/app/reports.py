"""Report listing, retrieval and PDF rendering for the reporting service."""

import subprocess

STORE = "/var/lib/reports"


def list_reports(request_args: dict[str, str]) -> list[str]:
    """Handle GET /reports. Returns the names of the stored reports."""
    del request_args
    return ["q1-summary", "q2-summary"]


def get_report(request_args: dict[str, str]) -> str:
    """Handle GET /reports/detail. `name` selects one of the stored reports."""
    name = request_args.get("name", "")
    if name not in list_reports({}):
        raise ValueError("unknown report")
    return f"{STORE}/{name}.json"


def render_pdf(request_args: dict[str, str]) -> bytes:
    """Render a stored report to PDF with the wkhtmltopdf binary.

    `source` is the report filename relative to STORE.
    """
    source = request_args.get("source", "")
    subprocess.run(f"wkhtmltopdf {STORE}/{source} /tmp/out.pdf", shell=True, check=True)
    with open("/tmp/out.pdf", "rb") as handle:
        return handle.read()
