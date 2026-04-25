"""Tests for PDF-to-text and format conversion utilities."""

import pytest

from nist_mcp.convert import _parse_page_range
from nist_mcp.safety import (
    ALLOWED_DOCUMENT_HOSTS,
    safe_filename_from_url,
    validate_https_url,
)


class TestPageRangeParsing:
    def test_single_page(self):
        assert _parse_page_range("3") == [2]

    def test_range_and_comma_list(self):
        assert _parse_page_range("1-3, 5") == [0, 1, 2, 4]

    @pytest.mark.parametrize("pages", ["0", "-1", "5-3", "1-", "1,,2", "abc"])
    def test_invalid_ranges(self, pages: str):
        with pytest.raises(ValueError):
            _parse_page_range(pages)

    def test_page_count_limit(self):
        with pytest.raises(ValueError, match="limited to 50 pages"):
            _parse_page_range("1-51")


class TestDownloadSafety:
    def test_validate_https_url_allows_nist_hosts(self):
        url = "https://csrc.nist.gov/files/pubs/sp/800/53/final.pdf"
        assert validate_https_url(url, allowed_hosts=ALLOWED_DOCUMENT_HOSTS) == url

    @pytest.mark.parametrize(
        "url",
        [
            "http://csrc.nist.gov/file.pdf",
            "https://127.0.0.1/file.pdf",
            "https://example.com/file.pdf",
        ],
    )
    def test_validate_https_url_rejects_unsafe_targets(self, url: str):
        with pytest.raises(ValueError):
            validate_https_url(url, allowed_hosts=ALLOWED_DOCUMENT_HOSTS)

    def test_safe_filename_from_url_sanitizes_name(self):
        assert (
            safe_filename_from_url("https://csrc.nist.gov/a/b/My File (final).pdf")
            == "My_File_final_.pdf"
        )
