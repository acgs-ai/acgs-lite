#!/usr/bin/env python3
"""Generate Cloudflare Workers Static Assets ``_headers`` with hash-based CSP.

Scans the built MkDocs documentation directory (``<site-dir>/<docs-subdir>``),
computes exact SHA-256 hashes for every executable inline ``<script>`` emitted
by MkDocs Material, discovers content-hashed static assets, and writes
``<site-dir>/_headers`` so Cloudflare serves ``/docs/*`` directly from Static
Assets with zero Worker invocations billed.

Security invariants:
- ``script-src`` never uses ``'unsafe-inline'`` or ``'unsafe-eval'``; only
  ``'self'`` plus build-time ``'sha256-...'`` hashes are allowed.
- Inline DOM event handler attributes (``on*=``) and external third-party
  ``<script src="https://...">`` tags fail the build closed.
- Every narrower ``Cache-Control`` rule emits ``! Cache-Control`` first so
  Cloudflare's top-down header inheritance never emits duplicate headers.
- Enforces Cloudflare's hard limits (<= 100 URL rules, <= 2,000 chars/line).

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import html
import re
import sys
from collections.abc import Sequence
from html.parser import HTMLParser
from pathlib import Path

HASHED_ASSET_RE = re.compile(r"\.[0-9a-f]{8}\.min\.(?:js|css)(?:\.map)?$", re.IGNORECASE)
_NON_SELF_SCRIPT_SRC_RE = re.compile(r"^(?:[a-z][a-z0-9+.-]*:|//)", re.IGNORECASE)
_ASCII_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]+")
_URL_ATTRS: frozenset[str] = frozenset(
    {"href", "src", "action", "formaction", "xlink:href", "data"}
)
MAX_CLOUDFLARE_RULES = 100
MAX_CLOUDFLARE_LINE_LEN = 2000

# HTML5 executable <script> types (lowercased MIME essence before ';').
# Omitted / empty type defaults to classic JS. Non-JS types such as
# "application/json" (MkDocs Material's #__config block) are data blocks.
_EXECUTABLE_SCRIPT_TYPES: frozenset[str] = frozenset(
    {
        "",
        "module",
        "importmap",
        "speculationrules",
        "text/javascript",
        "application/javascript",
        "text/ecmascript",
        "application/ecmascript",
        "text/javascript1.0",
        "text/javascript1.1",
        "text/javascript1.2",
        "text/javascript1.3",
        "text/javascript1.4",
        "text/javascript1.5",
        "text/jscript",
        "text/livescript",
        "text/x-ecmascript",
        "text/x-javascript",
        "application/x-ecmascript",
        "application/x-javascript",
    }
)

# Shared preventative security headers (kept in lockstep with worker.js).
BASE_SECURITY_HEADERS: tuple[tuple[str, str], ...] = (
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
    ("Permissions-Policy", "camera=(), geolocation=(), microphone=()"),
    ("Cross-Origin-Opener-Policy", "same-origin-allow-popups"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
)

HTML_CACHE_CONTROL = "public, max-age=300, stale-while-revalidate=86400"
STATIC_CACHE_CONTROL = "public, max-age=3600, stale-while-revalidate=86400"
IMMUTABLE_CACHE_CONTROL = "public, max-age=31536000, immutable"

UNHASHED_STATIC_SUBPATHS: tuple[str, ...] = (
    "search/search_index.json",
    "sitemap.xml",
    "sitemap.xml.gz",
    "objects.inv",
)


class _DocsHtmlAuditParser(HTMLParser):
    """Extract executable inline scripts and audit for CSP-incompatible constructs."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self.inline_scripts: list[str] = []
        self.event_handlers: list[tuple[str, str]] = []
        self.javascript_urls: list[tuple[str, str, str]] = []
        self.external_script_srcs: list[str] = []
        self._in_exec_inline_script = False
        self._script_chunks: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_lower = tag.lower()
        attr_map: dict[str, str] = {}
        for name, value in attrs:
            lname = name.lower()
            val = value or ""
            attr_map[lname] = val
            if lname.startswith("on") and len(lname) > 2 and lname[2:].isalpha():
                self.event_handlers.append((tag_lower, lname))
            elif lname in _URL_ATTRS and val:
                decoded = _ASCII_CTRL_RE.sub("", html.unescape(val)).strip()
                if decoded.lower().startswith("javascript:"):
                    self.javascript_urls.append((tag_lower, lname, val))

        if tag_lower != "script":
            return

        raw_src = attr_map.get("src", "")
        src = _ASCII_CTRL_RE.sub("", html.unescape(raw_src)).strip()
        if src:
            if _NON_SELF_SCRIPT_SRC_RE.match(src):
                self.external_script_srcs.append(src)
            return

        script_type = html.unescape(attr_map.get("type", "")).split(";", 1)[0].strip().lower()
        if script_type in _EXECUTABLE_SCRIPT_TYPES:
            self._in_exec_inline_script = True
            self._script_chunks = []

    def handle_data(self, data: str) -> None:
        if self._in_exec_inline_script:
            self._script_chunks.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script" and self._in_exec_inline_script:
            body = "".join(self._script_chunks)
            self._in_exec_inline_script = False
            self._script_chunks = []
            if body:
                self.inline_scripts.append(body)


def hash_inline_script(body: str) -> str:
    """Return the CSP ``sha256-<base64>`` token for an inline ``<script>`` body.

    Applies HTML5 newline normalization (``\\r\\n`` and ``\\r`` -> ``\\n``) so the
    digest matches browser CSP verification byte-for-byte.
    """
    normalized = body.replace("\r\n", "\n").replace("\r", "\n")
    digest = hashlib.sha256(normalized.encode("utf-8")).digest()
    return f"sha256-{base64.b64encode(digest).decode('ascii')}"


def audit_docs_html(docs_dir: Path) -> list[str]:
    """Audit all HTML files under *docs_dir* and return sorted unique CSP script hashes."""
    html_files = sorted(docs_dir.rglob("*.html"))
    if not html_files:
        raise ValueError(f"No HTML files found under {docs_dir}; run mkdocs build first.")

    hashes: set[str] = set()
    event_errors: list[str] = []
    js_url_errors: list[str] = []
    external_errors: list[str] = []

    for html_path in html_files:
        parser = _DocsHtmlAuditParser()
        parser.feed(html_path.read_text(encoding="utf-8"))
        parser.close()

        rel = html_path.relative_to(docs_dir)
        for tag, attr in parser.event_handlers:
            event_errors.append(f"{rel}: <{tag} {attr}=...>")
        for tag, attr, val in parser.javascript_urls:
            js_url_errors.append(f"{rel}: <{tag} {attr}={val!r}>")
        for src in parser.external_script_srcs:
            external_errors.append(f"{rel}: <script src={src!r}>")
        for body in parser.inline_scripts:
            hashes.add(hash_inline_script(body))

    if event_errors:
        sample = ", ".join(event_errors[:10])
        raise ValueError(f"Inline DOM event handler(s) break hash-only script-src CSP: {sample}")
    if js_url_errors:
        sample = ", ".join(js_url_errors[:10])
        raise ValueError(f"javascript: URL(s) break hash-only script-src CSP: {sample}")
    if external_errors:
        sample = ", ".join(external_errors[:10])
        raise ValueError(f"External or non-self <script src> violates script-src 'self': {sample}")

    return sorted(hashes)


def discover_hashed_assets(docs_dir: Path, docs_prefix: str) -> list[str]:
    """Return sorted URL paths of content-hashed immutable assets under *docs_dir*/assets."""
    assets_dir = docs_dir / "assets"
    if not assets_dir.is_dir():
        return []
    prefix = "/" + docs_prefix.strip("/")
    paths: list[str] = []
    for asset in sorted(assets_dir.rglob("*")):
        if asset.is_file() and HASHED_ASSET_RE.search(asset.name):
            rel = asset.relative_to(docs_dir).as_posix()
            paths.append(f"{prefix}/{rel}")
    return paths


def build_docs_csp(script_hashes: Sequence[str]) -> str:
    """Build a strict CSP with hash-only inline script execution (no 'unsafe-inline').

    ``style-src`` retains ``'unsafe-inline'`` because Markdown table alignment
    emits ``style="text-align: ..."`` attributes and MkDocs Material updates
    element inline styles / CSS custom properties dynamically; inline styles do
    not permit script execution.
    """
    script_tokens = ["'self'", *(f"'{h}'" for h in script_hashes)]
    return "; ".join(
        [
            "default-src 'self'",
            f"script-src {' '.join(script_tokens)}",
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
            "font-src 'self' https://fonts.gstatic.com data:",
            "img-src 'self' data: https:",
            "connect-src 'self' https://api.github.com",
            "worker-src 'self'",
            "object-src 'none'",
            "base-uri 'self'",
            "frame-ancestors 'none'",
            "form-action 'self'",
        ]
    )


def render_headers_file(
    *,
    csp: str,
    docs_prefix: str,
    hashed_assets: Sequence[str],
) -> str:
    """Render and validate a Cloudflare Workers Static Assets ``_headers`` file."""
    prefix = "/" + docs_prefix.strip("/")
    rules: list[tuple[str, list[str]]] = []

    root_headers = [f"{name}: {value}" for name, value in BASE_SECURITY_HEADERS]
    root_headers.append(f"Content-Security-Policy: {csp}")
    root_headers.append(f"Cache-Control: {HTML_CACHE_CONTROL}")
    rules.append(("/*", root_headers))

    rules.append(
        (
            f"{prefix}/assets/*",
            [
                "! Cache-Control",
                f"Cache-Control: {STATIC_CACHE_CONTROL}",
            ],
        )
    )

    for subpath in UNHASHED_STATIC_SUBPATHS:
        rules.append(
            (
                f"{prefix}/{subpath}",
                [
                    "! Cache-Control",
                    f"Cache-Control: {STATIC_CACHE_CONTROL}",
                ],
            )
        )

    for asset_path in hashed_assets:
        rules.append(
            (
                asset_path,
                [
                    "! Cache-Control",
                    f"Cache-Control: {IMMUTABLE_CACHE_CONTROL}",
                ],
            )
        )

    if len(rules) > MAX_CLOUDFLARE_RULES:
        raise ValueError(
            f"Generated {len(rules)} Cloudflare _headers rules, exceeding limit "
            f"of {MAX_CLOUDFLARE_RULES}"
        )

    lines: list[str] = [
        "# Auto-generated by scripts/generate_cf_headers.py — do not edit by hand.",
        "# Offloads static /docs/* security headers, SHA-256 CSP, and Cache-Control",
        "# to Cloudflare Static Assets (zero Worker invocations billed).",
        "",
    ]
    for pattern, header_lines in rules:
        if "\n" in pattern or "\r" in pattern:
            raise ValueError(f"Invalid newline in _headers path pattern: {pattern!r}")
        lines.append(pattern)
        for hline in header_lines:
            if "\n" in hline or "\r" in hline:
                raise ValueError(f"Invalid newline in _headers header line: {hline!r}")
            formatted = f"  {hline}"
            if len(formatted) > MAX_CLOUDFLARE_LINE_LEN:
                raise ValueError(
                    f"_headers line exceeds Cloudflare's {MAX_CLOUDFLARE_LINE_LEN}-char limit "
                    f"({len(formatted)} chars): {formatted[:80]}..."
                )
            lines.append(formatted)
        lines.append("")

    return "\n".join(lines)


def generate_headers(site_dir: Path, docs_subdir: str = "docs") -> str:
    """Compute the full ``_headers`` text for a built MkDocs site."""
    docs_dir = site_dir / docs_subdir
    if not docs_dir.is_dir():
        raise ValueError(f"Docs build directory not found: {docs_dir}")
    script_hashes = audit_docs_html(docs_dir)
    hashed_assets = discover_hashed_assets(docs_dir, docs_subdir)
    csp = build_docs_csp(script_hashes)
    return render_headers_file(
        csp=csp,
        docs_prefix=docs_subdir,
        hashed_assets=hashed_assets,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--site-dir",
        type=Path,
        default=Path("site"),
        help="Cloudflare Static Assets root directory (default: site)",
    )
    parser.add_argument(
        "--docs-subdir",
        default="docs",
        help="MkDocs output subdirectory under --site-dir (default: docs)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify existing <site-dir>/_headers matches freshly generated output",
    )
    args = parser.parse_args(argv)

    try:
        rendered = generate_headers(args.site_dir, docs_subdir=args.docs_subdir)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    out_path = args.site_dir / "_headers"
    if args.check:
        if not out_path.is_file():
            print(f"error: missing {out_path}; run scripts/generate_cf_headers.py", file=sys.stderr)
            return 1
        existing = out_path.read_text(encoding="utf-8")
        if existing != rendered:
            print(f"error: {out_path} is out of date with built docs", file=sys.stderr)
            return 1
        print(f"OK: {out_path} is up to date.")
        return 0

    out_path.write_text(rendered, encoding="utf-8")
    rule_count = sum(
        1 for line in rendered.splitlines() if line and not line.startswith(("#", " "))
    )
    print(f"Wrote {out_path} ({rule_count} rules, {len(rendered)} bytes).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
