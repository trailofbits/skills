---
max_turns: 8
timeout_seconds: 180
allowed_tools: [Skill, Read, Grep, Glob]
runs: 3
---
Can you audit this module for vulnerabilities? Nothing has been reported against it, we are
just working through the codebase file by file.

```python
# api/pagination.py
from dataclasses import dataclass

DEFAULT_PAGE_SIZE = 25
MAX_PAGE_SIZE = 100


@dataclass(frozen=True)
class Page:
    offset: int
    limit: int


def parse_page(params):
    """Build a Page from raw query-string params."""
    try:
        page = int(params.get("page", 1))
    except (TypeError, ValueError):
        page = 1
    try:
        size = int(params.get("size", DEFAULT_PAGE_SIZE))
    except (TypeError, ValueError):
        size = DEFAULT_PAGE_SIZE

    page = max(page, 1)
    size = min(max(size, 1), MAX_PAGE_SIZE)
    return Page(offset=(page - 1) * size, limit=size)


def page_links(base_url, page, total):
    """Build prev/next link hints for the response envelope."""
    last = max((total + page.limit - 1) // page.limit, 1)
    current = page.offset // page.limit + 1
    links = {"self": f"{base_url}?page={current}&size={page.limit}"}
    if current > 1:
        links["prev"] = f"{base_url}?page={current - 1}&size={page.limit}"
    if current < last:
        links["next"] = f"{base_url}?page={current + 1}&size={page.limit}"
    return links
