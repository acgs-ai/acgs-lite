"""Tests for scripts/generate_cf_headers.py (Cloudflare Static Assets _headers & CSP)."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import re
from pathlib import Path
from typing import Any

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT_PATH = _REPO_ROOT / "scripts" / "generate_cf_headers.py"


def _load_generator() -> Any:
    spec = importlib.util.spec_from_file_location("generate_cf_headers", _SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gen = _load_generator()


def _sha256_token(text: str) -> str:
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    return f"sha256-{base64.b64encode(digest).decode('ascii')}"


class TestGenerateCfHeaders:
    def test_extracts_executable_inline_scripts_and_skips_json_comments_and_src(
        self, tmp_path: Path
    ) -> None:
        docs_dir = tmp_path / "docs"
        docs_dir.mkdir()
        (docs_dir / "index.html").write_text(
            "<!doctype html><html><head>"
            "<!-- <script>alert('commented-out')</script> -->"
            '<script src="assets/javascripts/bundle.1234abcd.min.js"></script>'
            '<script id="__config" type="application/json">{"base":"."}</script>'
            "<script>var palette=1;\r\nvar x=2;</script>"
            '<script type="text/javascript; charset=utf-8">console.log(1)</script>'
            "<pre><code>&lt;script&gt;not_a_tag()&lt;/script&gt;</code></pre>"
            "</head><body>ok</body></html>",
            encoding="utf-8",
        )

        hashes = gen.audit_docs_html(docs_dir)
        expected = sorted(
            [
                _sha256_token("var palette=1;\nvar x=2;"),
                _sha256_token("console.log(1)"),
            ]
        )
        assert hashes == expected

    def test_rejects_inline_event_handlers_fail_closed(self, tmp_path: Path) -> None:
        docs_dir = tmp_path / "docs"
        docs_dir.mkdir()
        (docs_dir / "bad.html").write_text(
            '<html><body><button onclick="doThing()">Go</button></body></html>',
            encoding="utf-8",
        )
        with pytest.raises(ValueError, match="Inline DOM event handler"):
            gen.audit_docs_html(docs_dir)

    @pytest.mark.parametrize(
        "src",
        [
            "https://cdn.example.com/x.js",
            "HTTPS://cdn.example.com/x.js",
            "//cdn.example.com/x.js",
            "data:text/javascript,alert(1)",
            "blob:https://acgs.ai/abc",
        ],
    )
    def test_rejects_external_or_non_self_script_src(self, tmp_path: Path, src: str) -> None:
        docs_dir = tmp_path / "docs"
        docs_dir.mkdir()
        (docs_dir / "bad.html").write_text(
            f'<html><head><script src="{src}"></script></head></html>',
            encoding="utf-8",
        )
        with pytest.raises(ValueError, match="External or non-self <script src>"):
            gen.audit_docs_html(docs_dir)

    @pytest.mark.parametrize(
        "snippet",
        [
            '<a href="javascript:alert(1)">x</a>',
            '<a href="  JaVa&#x09;ScRiPt:alert(1)">x</a>',
            '<form action="JAVASCRIPT:void(0)"></form>',
            '<script src="javascript:alert(1)"></script>',
        ],
    )
    def test_rejects_javascript_urls_fail_closed(self, tmp_path: Path, snippet: str) -> None:
        docs_dir = tmp_path / "docs"
        docs_dir.mkdir()
        (docs_dir / "bad.html").write_text(f"<html><body>{snippet}</body></html>", encoding="utf-8")
        with pytest.raises(ValueError, match="javascript: URL"):
            gen.audit_docs_html(docs_dir)

    def test_hashes_speculationrules_inline_scripts(self, tmp_path: Path) -> None:
        docs_dir = tmp_path / "docs"
        docs_dir.mkdir()
        rules_json = '{"prerender":[{"where":{"href_matches":"/docs/*"}}]}'
        (docs_dir / "index.html").write_text(
            f'<html><head><script type="speculationrules">{rules_json}</script></head></html>',
            encoding="utf-8",
        )
        assert gen.audit_docs_html(docs_dir) == [_sha256_token(rules_json)]

    def test_rejects_empty_docs_directory(self, tmp_path: Path) -> None:
        docs_dir = tmp_path / "docs"
        docs_dir.mkdir()
        with pytest.raises(ValueError, match="No HTML files found"):
            gen.audit_docs_html(docs_dir)

    def test_rendered_headers_detaches_cache_control_and_uses_hash_only_script_src(
        self, tmp_path: Path
    ) -> None:
        docs_dir = tmp_path / "docs"
        js_dir = docs_dir / "assets" / "javascripts"
        js_dir.mkdir(parents=True)
        (docs_dir / "index.html").write_text(
            "<html><head><script>window.__ok=1;</script></head></html>",
            encoding="utf-8",
        )
        (js_dir / "bundle.a5f9d56c.min.js").write_text("/*bundle*/", encoding="utf-8")
        (js_dir / "bundle.a5f9d56c.min.js.map").write_text("{}", encoding="utf-8")
        (docs_dir / "assets" / "_mkdocstrings.css").write_text("body{}", encoding="utf-8")

        rendered = gen.generate_headers(tmp_path)
        assert "'unsafe-inline'" not in _extract_directive(rendered, "script-src")
        assert "'unsafe-eval'" not in _extract_directive(rendered, "script-src")
        assert f"'{_sha256_token('window.__ok=1;')}'" in _extract_directive(rendered, "script-src")

        # Every narrower Cache-Control block must detach inherited Cache-Control first.
        blocks = _parse_blocks(rendered)
        assert "/*" in blocks
        assert "/docs/assets/*" in blocks
        assert "/docs/assets/javascripts/bundle.a5f9d56c.min.js" in blocks
        assert "/docs/assets/javascripts/bundle.a5f9d56c.min.js.map" in blocks
        assert "/docs/assets/_mkdocstrings.css" not in blocks  # covered by /docs/assets/*

        for pattern, lines in blocks.items():
            if pattern == "/*":
                assert any(line.startswith("Cache-Control: public, max-age=300,") for line in lines)
                continue
            assert lines[0] == "! Cache-Control", f"{pattern} missing ! Cache-Control detach"
            assert lines[1].startswith("Cache-Control: ")

        assert blocks["/docs/assets/javascripts/bundle.a5f9d56c.min.js"][1] == (
            "Cache-Control: public, max-age=31536000, immutable"
        )
        assert all(len(line) <= gen.MAX_CLOUDFLARE_LINE_LEN for line in rendered.splitlines())
        assert len(blocks) <= gen.MAX_CLOUDFLARE_RULES

    def test_cli_write_and_check_roundtrip(self, tmp_path: Path) -> None:
        docs_dir = tmp_path / "docs"
        docs_dir.mkdir()
        (docs_dir / "index.html").write_text(
            "<html><head><script>console.log('hi')</script></head></html>",
            encoding="utf-8",
        )

        # Missing _headers -> --check fails.
        assert gen.main(["--site-dir", str(tmp_path), "--check"]) == 1
        # Write succeeds and --check passes.
        assert gen.main(["--site-dir", str(tmp_path)]) == 0
        assert gen.main(["--site-dir", str(tmp_path), "--check"]) == 0
        # Tampering _headers -> --check fails.
        headers_file = tmp_path / "_headers"
        headers_file.write_text(headers_file.read_text(encoding="utf-8") + "\n# drift\n")
        assert gen.main(["--site-dir", str(tmp_path), "--check"]) == 1

    def test_enforces_cloudflare_rule_limit(self) -> None:
        too_many_assets = [f"/docs/assets/f{i}.12345678.min.js" for i in range(105)]
        with pytest.raises(ValueError, match="exceeding limit of 100"):
            gen.render_headers_file(
                csp=gen.build_docs_csp([]),
                docs_prefix="docs",
                hashed_assets=too_many_assets,
            )

    def test_security_headers_match_worker_js(self) -> None:
        worker_src = (_REPO_ROOT / "worker.js").read_text(encoding="utf-8")
        for header_name, header_value in gen.BASE_SECURITY_HEADERS:
            expected_pair = f'"{header_name}": "{header_value}"'
            assert expected_pair in worker_src, (
                f"Header drift between generate_cf_headers.py and worker.js: {expected_pair}"
            )
        # Non-script-src CSP directives and Cache-Control policies must also stay in lockstep.
        for directive in gen.build_docs_csp([]).split("; "):
            if directive.startswith("script-src "):
                continue
            assert f'"{directive}"' in worker_src, (
                f"CSP directive drift between generate_cf_headers.py and worker.js: {directive}"
            )
        for cc in (gen.HTML_CACHE_CONTROL, gen.STATIC_CACHE_CONTROL, gen.IMMUTABLE_CACHE_CONTROL):
            assert f'"{cc}"' in worker_src, (
                f"Cache-Control drift between generate_cf_headers.py and worker.js: {cc}"
            )


def _extract_directive(headers_text: str, directive: str) -> str:
    match = re.search(r"Content-Security-Policy:\s*(.+)", headers_text)
    assert match is not None
    for part in match.group(1).split(";"):
        stripped = part.strip()
        if stripped.startswith(f"{directive} "):
            return stripped
    raise AssertionError(f"Directive {directive!r} not found in CSP")


def _parse_blocks(headers_text: str) -> dict[str, list[str]]:
    blocks: dict[str, list[str]] = {}
    current: str | None = None
    for raw in headers_text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if not raw.startswith(" "):
            current = raw.strip()
            blocks[current] = []
        else:
            assert current is not None
            blocks[current].append(raw.strip())
    return blocks
