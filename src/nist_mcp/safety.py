"""Safety helpers for MCP tool inputs and externally sourced outputs."""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import unquote, urlparse


ALLOWED_DOCUMENT_HOSTS = frozenset(
    {
        "csrc.nist.gov",
        "nvlpubs.nist.gov",
        "nist.gov",
        "pages.nist.gov",
        "www.nist.gov",
    }
)

MAX_DOCUMENT_BYTES = 100 * 1024 * 1024
MAX_PAGES_PER_REQUEST = 50

_SAFE_FILENAME_CHARS = re.compile(r"[^A-Za-z0-9._-]+")


def validate_https_url(url: str, *, allowed_hosts: frozenset[str]) -> str:
    """Return *url* if it is HTTPS and targets an explicitly allowed host."""
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or host not in allowed_hosts:
        allowed = ", ".join(sorted(allowed_hosts))
        raise ValueError(f"URL must use HTTPS and target one of: {allowed}")
    return url


def safe_filename_from_url(url: str, *, default: str = "document") -> str:
    """Extract a cache-safe filename from a URL path."""
    parsed = urlparse(url)
    name = unquote(Path(parsed.path).name).strip()
    if not name or name in {".", ".."}:
        name = default

    name = _SAFE_FILENAME_CHARS.sub("_", name)
    name = name.strip("._") or default
    return name[:180]


def validate_page_range(pages: str) -> list[int]:
    """Parse a 1-based page range into 0-based page indexes with tight bounds."""
    result: list[int] = []

    for raw_part in pages.split(","):
        part = raw_part.strip()
        if not part:
            raise ValueError("Page ranges cannot contain empty segments.")

        if "-" in part:
            start_s, end_s = part.split("-", 1)
            if not start_s.strip().isdigit() or not end_s.strip().isdigit():
                raise ValueError("Page ranges must use positive integers, e.g. '1-5'.")
            start = int(start_s.strip())
            end = int(end_s.strip())
            if start > end:
                raise ValueError("Page range start must be less than or equal to end.")
            result.extend(range(start - 1, end))
        else:
            if not part.isdigit():
                raise ValueError("Page ranges must use positive integers, e.g. '3'.")
            result.append(int(part) - 1)

    if any(page < 0 for page in result):
        raise ValueError("Page numbers are 1-based and must be greater than zero.")

    if len(result) > MAX_PAGES_PER_REQUEST:
        raise ValueError(
            f"Page requests are limited to {MAX_PAGES_PER_REQUEST} pages. "
            "Use a narrower range."
        )

    return result
