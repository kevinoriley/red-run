"""MCP server providing headless browser automation for pentesting subagents.

Provides eleven tools:
- browser_open: Create session + navigate to URL
- browser_navigate: Navigate within existing session
- browser_get_page: Re-read page content (optionally scoped to CSS selector)
- browser_click: Click element + wait for navigation
- browser_fill: Fill single form field
- browser_select: Select dropdown option
- browser_screenshot: Take PNG screenshot
- browser_cookies: Get all cookies as JSON
- browser_evaluate: Run JavaScript in page context
- close_browser: Close session
- list_browser_sessions: List all active sessions

Solves the web interaction problem — curl can't handle CSRF tokens, session
rotation, JavaScript-rendered forms, or multi-step authentication flows. This
server manages a headless Chromium browser with persistent sessions that
maintain cookies, localStorage, and state across tool calls.

Usage:
    uv run python server.py
"""

from __future__ import annotations

import asyncio
import atexit
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from markdownify import markdownify
from mcp.server.fastmcp import FastMCP

# Resolve engagement directory relative to the project root, not the server's
# own directory.  uv run --directory changes cwd to tools/browser-server/, so
# bare Path("engagement/...") would land artifacts inside the tools tree.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

# Content size cap — truncate HTML-to-markdown output at 50KB
MAX_CONTENT_SIZE = 50 * 1024


def _html_to_markdown(html: str) -> str:
    """Convert HTML to markdown, stripping script/style tags first."""
    # Strip <script> and <style> blocks before conversion
    cleaned = re.sub(
        r"<script[^>]*>[\s\S]*?</script>", "", html, flags=re.IGNORECASE
    )
    cleaned = re.sub(
        r"<style[^>]*>[\s\S]*?</style>", "", cleaned, flags=re.IGNORECASE
    )
    md = markdownify(cleaned, heading_style="ATX", strip=["img"])
    # Collapse excessive whitespace
    md = re.sub(r"\n{3,}", "\n\n", md).strip()
    if len(md) > MAX_CONTENT_SIZE:
        md = md[:MAX_CONTENT_SIZE] + "\n\n[truncated — content exceeded 50KB]"
    return md


def create_server() -> FastMCP:
    """Create and configure the browser MCP server."""
    mcp = FastMCP(
        "red-run-browser-server",
        instructions=(
            "Provides headless browser automation for red-run subagents. "
            "Use browser_open to create sessions and navigate to URLs, "
            "browser_fill/browser_click for form interaction, "
            "browser_cookies for session state, browser_evaluate for "
            "JavaScript execution, and browser_screenshot for evidence. "
            "Handles CSRF tokens, session rotation, and JS-rendered content "
            "that curl cannot."
        ),
    )

    # Shared state — browser instance + sessions
    browser_instance = {"browser": None, "playwright": None}
    sessions: dict[str, dict] = {}

    async def _ensure_browser():
        """Launch Chromium lazily on first use."""
        if browser_instance["browser"] is None:
            from playwright.async_api import async_playwright

            pw = await async_playwright().start()
            browser_instance["playwright"] = pw
            browser_instance["browser"] = await pw.chromium.launch(
                headless=True,
            )
        return browser_instance["browser"]

    def _cleanup() -> None:
        """Close browser on exit."""
        browser = browser_instance.get("browser")
        pw = browser_instance.get("playwright")
        if browser:
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    loop.create_task(browser.close())
                else:
                    loop.run_until_complete(browser.close())
            except Exception:
                pass
        if pw:
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    loop.create_task(pw.stop())
                else:
                    loop.run_until_complete(pw.stop())
            except Exception:
                pass

    atexit.register(_cleanup)

    @mcp.tool()
    async def browser_open(
        url: str,
        ignore_tls: bool = True,
    ) -> str:
        """Create session + navigate to URL.

        Launches a new browser context with its own cookie jar and
        navigates to the given URL. Returns page content as markdown.

        Args:
            url: URL to navigate to (e.g., "https://target.htb/login").
            ignore_tls: Ignore TLS certificate errors (default True).
        """
        browser = await _ensure_browser()
        session_id = str(uuid.uuid4())[:8]

        try:
            context = await browser.new_context(
                ignore_https_errors=ignore_tls,
            )
            page = await context.new_page()
            response = await page.goto(url, wait_until="load", timeout=30000)

            content = await page.content()
            md = _html_to_markdown(content)
            title = await page.title()

            sessions[session_id] = {
                "context": context,
                "page": page,
                "created_at": datetime.now(tz=timezone.utc).isoformat(),
                "ignore_tls": ignore_tls,
            }

            return json.dumps({
                "session_id": session_id,
                "url": page.url,
                "title": title,
                "status": response.status if response else None,
                "content": md,
            }, indent=2)

        except Exception as e:
            # Clean up on failure
            try:
                await context.close()
            except Exception:
                pass
            return f"ERROR: Failed to open {url} — {e}"

    @mcp.tool()
    async def browser_navigate(
        session_id: str,
        url: str,
    ) -> str:
        """Navigate within an existing session.

        Navigates the session's page to a new URL, preserving cookies
        and session state.

        Args:
            session_id: Session ID from browser_open.
            url: URL to navigate to.
        """
        if session_id not in sessions:
            available = ", ".join(sessions.keys()) if sessions else "none"
            return f"ERROR: Session '{session_id}' not found. Available: {available}"

        page = sessions[session_id]["page"]

        try:
            response = await page.goto(url, wait_until="load", timeout=30000)
            content = await page.content()
            md = _html_to_markdown(content)
            title = await page.title()

            return json.dumps({
                "url": page.url,
                "title": title,
                "status": response.status if response else None,
                "content": md,
            }, indent=2)

        except Exception as e:
            return f"ERROR: Navigation failed — {e}"

    @mcp.tool()
    async def browser_get_page(
        session_id: str,
        selector: str = "",
    ) -> str:
        """Re-read page content, optionally scoped to a CSS selector.

        Useful after clicking buttons or waiting for dynamic content to
        load. Without a selector, returns the full page as markdown.

        Args:
            session_id: Session ID from browser_open.
            selector: Optional CSS selector to scope content
                      (e.g., "form#login", "div.results", "table").
        """
        if session_id not in sessions:
            available = ", ".join(sessions.keys()) if sessions else "none"
            return f"ERROR: Session '{session_id}' not found. Available: {available}"

        page = sessions[session_id]["page"]

        try:
            if selector:
                element = await page.query_selector(selector)
                if not element:
                    return f"ERROR: Selector '{selector}' not found on page."
                html = await element.inner_html()
            else:
                html = await page.content()

            md = _html_to_markdown(html)
            title = await page.title()

            return json.dumps({
                "url": page.url,
                "title": title,
                "selector": selector or "(full page)",
                "content": md,
            }, indent=2)

        except Exception as e:
            return f"ERROR: Failed to read page — {e}"

    @mcp.tool()
    async def browser_click(
        session_id: str,
        selector: str,
        wait_until: str = "load",
    ) -> str:
        """Click an element and wait for navigation/loading.

        Clicks the element matching the CSS selector and waits for the
        page to reach the specified load state.

        Args:
            session_id: Session ID from browser_open.
            selector: CSS selector of element to click
                      (e.g., "button[type=submit]", "a.login-link").
            wait_until: Wait condition after click — "load",
                        "domcontentloaded", or "networkidle".
        """
        if session_id not in sessions:
            available = ", ".join(sessions.keys()) if sessions else "none"
            return f"ERROR: Session '{session_id}' not found. Available: {available}"

        page = sessions[session_id]["page"]

        try:
            # Click and optionally wait for navigation
            async with page.expect_navigation(
                wait_until=wait_until, timeout=15000
            ) as _:
                await page.click(selector, timeout=5000)

        except Exception:
            # Navigation may not happen (e.g., AJAX form submit, JS action)
            # — that's fine, just click without waiting for navigation
            try:
                await page.click(selector, timeout=5000)
                # Brief wait for any dynamic content
                await page.wait_for_timeout(1000)
            except Exception as e:
                return f"ERROR: Click failed — {e}"

        try:
            content = await page.content()
            md = _html_to_markdown(content)
            title = await page.title()

            return json.dumps({
                "url": page.url,
                "title": title,
                "clicked": selector,
                "content": md,
            }, indent=2)

        except Exception as e:
            return f"ERROR: Failed to read page after click — {e}"

    @mcp.tool()
    async def browser_fill(
        session_id: str,
        selector: str,
        value: str,
    ) -> str:
        """Fill a single form field.

        Clears the field and types the value. Call once per field —
        for a login form, call browser_fill twice (username, password),
        then browser_click on the submit button.

        Args:
            session_id: Session ID from browser_open.
            selector: CSS selector of the input field
                      (e.g., "input[name=username]", "#password").
            value: Value to fill in the field.
        """
        if session_id not in sessions:
            available = ", ".join(sessions.keys()) if sessions else "none"
            return f"ERROR: Session '{session_id}' not found. Available: {available}"

        page = sessions[session_id]["page"]

        try:
            await page.fill(selector, value, timeout=5000)
            return json.dumps({
                "filled": selector,
                "value_length": len(value),
                "message": f"Filled '{selector}' with {len(value)} chars.",
            }, indent=2)

        except Exception as e:
            return f"ERROR: Fill failed — {e}"

    @mcp.tool()
    async def browser_select(
        session_id: str,
        selector: str,
        value: str,
    ) -> str:
        """Select a dropdown option.

        Selects an option in a <select> element by its value attribute.

        Args:
            session_id: Session ID from browser_open.
            selector: CSS selector of the <select> element
                      (e.g., "select[name=role]", "#country").
            value: The option value to select.
        """
        if session_id not in sessions:
            available = ", ".join(sessions.keys()) if sessions else "none"
            return f"ERROR: Session '{session_id}' not found. Available: {available}"

        page = sessions[session_id]["page"]

        try:
            selected = await page.select_option(selector, value, timeout=5000)
            return json.dumps({
                "selected": selector,
                "value": value,
                "result": selected,
            }, indent=2)

        except Exception as e:
            return f"ERROR: Select failed — {e}"

    @mcp.tool()
    async def browser_screenshot(
        session_id: str,
        save_to: str = "",
    ) -> str:
        """Take a PNG screenshot of the current page.

        Saves to the specified path or defaults to
        engagement/evidence/browser-<timestamp>.png.

        Args:
            session_id: Session ID from browser_open.
            save_to: Optional path to save screenshot. Defaults to
                     engagement/evidence/browser-<timestamp>.png.
        """
        if session_id not in sessions:
            available = ", ".join(sessions.keys()) if sessions else "none"
            return f"ERROR: Session '{session_id}' not found. Available: {available}"

        page = sessions[session_id]["page"]

        if save_to:
            path = Path(save_to)
        else:
            evidence_dir = _PROJECT_ROOT / "engagement" / "evidence"
            if evidence_dir.exists():
                ts = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                path = evidence_dir / f"browser-{ts}.png"
            else:
                path = _PROJECT_ROOT / f"browser-screenshot-{session_id}.png"

        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            await page.screenshot(path=str(path), full_page=True)

            return json.dumps({
                "screenshot": str(path),
                "url": page.url,
                "message": f"Screenshot saved to {path}",
            }, indent=2)

        except Exception as e:
            return f"ERROR: Screenshot failed — {e}"

    @mcp.tool()
    async def browser_cookies(
        session_id: str,
    ) -> str:
        """Get all cookies from the session.

        Returns all cookies as JSON, including name, value, domain,
        path, httpOnly, secure, and sameSite attributes.

        Args:
            session_id: Session ID from browser_open.
        """
        if session_id not in sessions:
            available = ", ".join(sessions.keys()) if sessions else "none"
            return f"ERROR: Session '{session_id}' not found. Available: {available}"

        context = sessions[session_id]["context"]

        try:
            cookies = await context.cookies()
            return json.dumps({
                "cookie_count": len(cookies),
                "cookies": cookies,
            }, indent=2)

        except Exception as e:
            return f"ERROR: Failed to get cookies — {e}"

    @mcp.tool()
    async def browser_evaluate(
        session_id: str,
        expression: str,
    ) -> str:
        """Run JavaScript in the page context.

        Escape hatch for anything not covered by other browser tools.
        Returns the expression's return value as JSON.

        Args:
            session_id: Session ID from browser_open.
            expression: JavaScript expression to evaluate
                        (e.g., "document.querySelector('meta[name=csrf-token]').content",
                        "document.cookie", "localStorage.getItem('token')").
        """
        if session_id not in sessions:
            available = ", ".join(sessions.keys()) if sessions else "none"
            return f"ERROR: Session '{session_id}' not found. Available: {available}"

        page = sessions[session_id]["page"]

        try:
            result = await page.evaluate(expression)
            return json.dumps({
                "expression": expression,
                "result": result,
            }, indent=2)

        except Exception as e:
            return f"ERROR: JS evaluation failed — {e}"

    @mcp.tool()
    async def close_browser(
        session_id: str,
    ) -> str:
        """Close a browser session.

        Closes the browser context and page, freeing resources.

        Args:
            session_id: Session ID to close.
        """
        if session_id not in sessions:
            available = ", ".join(sessions.keys()) if sessions else "none"
            return f"ERROR: Session '{session_id}' not found. Available: {available}"

        session = sessions.pop(session_id)

        try:
            await session["context"].close()
        except Exception:
            pass

        return json.dumps({
            "status": "closed",
            "session_id": session_id,
            "message": "Browser session closed.",
        }, indent=2)

    @mcp.tool()
    async def list_browser_sessions() -> str:
        """List all active browser sessions.

        Returns a summary of all open browser sessions with their URLs
        and creation timestamps.
        """
        if not sessions:
            return "No active browser sessions. Use browser_open() to start one."

        result = []
        for sid, session in sessions.items():
            try:
                url = session["page"].url
                title = await session["page"].title()
            except Exception:
                url = "(page closed)"
                title = ""

            result.append({
                "session_id": sid,
                "url": url,
                "title": title,
                "created_at": session["created_at"],
                "ignore_tls": session["ignore_tls"],
            })

        return json.dumps({"sessions": result}, indent=2)

    return mcp


def main() -> None:
    server = create_server()
    server.run()


if __name__ == "__main__":
    main()
