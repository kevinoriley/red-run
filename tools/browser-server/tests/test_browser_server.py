"""Unit tests for browser-server.

Tests _html_to_markdown() (pure function, no Playwright) and server creation.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add server directory to path so we can import server module
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from server import MAX_CONTENT_SIZE, _html_to_markdown, create_server


class TestHtmlToMarkdown:
    def test_strips_script_tags(self):
        html = "<p>Hello</p><script>alert('xss')</script><p>World</p>"
        md = _html_to_markdown(html)
        assert "alert" not in md
        assert "script" not in md
        assert "Hello" in md
        assert "World" in md

    def test_strips_style_tags(self):
        html = "<style>body { color: red; }</style><p>Content</p>"
        md = _html_to_markdown(html)
        assert "color" not in md
        assert "style" not in md
        assert "Content" in md

    def test_strips_nested_script(self):
        html = (
            '<script type="text/javascript">'
            'var x = "<script>nested</script>";'
            "</script>"
            "<p>Safe</p>"
        )
        md = _html_to_markdown(html)
        assert "Safe" in md
        # The nested script content should be removed
        assert "var x" not in md

    def test_truncates_at_50kb(self):
        # Create HTML that produces markdown larger than MAX_CONTENT_SIZE
        large_html = "<p>" + "A" * (MAX_CONTENT_SIZE + 1000) + "</p>"
        md = _html_to_markdown(large_html)
        assert len(md) <= MAX_CONTENT_SIZE + 100  # Allow for truncation notice
        assert "[truncated" in md

    def test_collapses_excessive_whitespace(self):
        html = "<p>One</p>\n\n\n\n\n<p>Two</p>"
        md = _html_to_markdown(html)
        assert "\n\n\n" not in md

    def test_empty_html(self):
        md = _html_to_markdown("")
        assert md == ""

    def test_basic_html_conversion(self):
        html = '<h1>Title</h1><p>Text</p><a href="https://example.com">Link</a>'
        md = _html_to_markdown(html)
        assert "Title" in md
        assert "Text" in md
        assert "Link" in md
        assert "example.com" in md


class TestServerCreation:
    def test_creates_server(self):
        server = create_server()
        assert server is not None

    def test_server_name(self):
        server = create_server()
        assert server.name == "red-run-browser-server"
