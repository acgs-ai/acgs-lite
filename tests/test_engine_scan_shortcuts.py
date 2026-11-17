"""Guards for the ``GovernanceEngine`` scan shortcuts (regex work skipped when provably safe).

The pure-Python matcher in ``acgs_lite.engine.core`` skips regex work when a cheaper
check proves the regex cannot match: a substring test for the negative-verb regex, an
ASCII-only required-literal gate in front of each rule pattern, and a keyword substring
gate in front of the keyword alternations for long texts. The safety property is
one-directional: a shortcut may say "skip" only when the regex would not have matched,
otherwise a forbidden action is allowed. These tests fail if that property is broken.

Layout:

* helper-vs-regex equivalence for the negative-verb helper and ``_is_plain_ascii``
* required-literal derivation (``_ascii_gate_literal_of``): exact outcomes for a table of
  patterns, plus "literal absent from text implies no regex match" over a corpus
* engine-level behaviour through ``GovernanceEngine.validate`` only: allow/deny pairs
  around the 64-character keyword-gate threshold, non-ASCII and mixed-case text, control
  characters, a seeded differential run against ``Rule.matches``, and spies showing that
  a shortcut actually engages
* the negative-verb fallback (regex used when it no longer equals its rebuild from the
  literal list)
* ``_runtime_active_rules`` (condition, expiry after construction, malformed timestamp)

Reaching into private helpers (``_has_negative_verb``, ``_is_plain_ascii``,
``_ascii_gate_literal_of``, ``_negative_verb_literals``, ``_NEGATIVE_VERB_LITERALS``,
``_runtime_active_rules``) is deliberate and limited to the equivalence, fallback and
rule-activation properties above. Engine-level shortcut behaviour is asserted through the
public ``validate`` API; the "shortcut engages" spies only replace the stdlib ``re``
module alias in the module under test and count calls.

The engine-level shortcut tests are skipped when the Aho-Corasick or Rust backend is
installed, because those backends bypass the pure-Python regex matcher.
"""

from __future__ import annotations

import functools
import random
import re
import sys
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from typing import Any

import pytest

import acgs_lite.constitution.rule as rule_module
import acgs_lite.engine.core as engine_core
from acgs_lite.audit import AuditLog
from acgs_lite.constitution import Constitution, Rule, Severity
from acgs_lite.constitution.analytics import (
    _NEGATIVE_VERBS_LIST,
    _NEGATIVE_VERBS_RE,
    _POSITIVE_VERBS_SET,
)
from acgs_lite.engine import GovernanceEngine
from acgs_lite.engine.core import normalize_for_matching
from acgs_lite.engine.matcher import _HAS_AHO, _HAS_RUST

pytestmark = pytest.mark.unit

requires_python_regex_backend = pytest.mark.skipif(
    _HAS_AHO or _HAS_RUST,
    reason="the scan shortcuts live in the pure-Python regex matcher; "
    "the Aho-Corasick and Rust backends bypass it",
)

_COMPILE_FLAGS = re.IGNORECASE | re.UNICODE

# Characters whose IGNORECASE folding reaches outside ASCII, or that normalization touches.
LONG_S = "\u017f"
DOTLESS_I = "\u0131"
KELVIN = "\u212a"
DOTTED_CAP_I = "\u0130"
E_ACUTE = "\u00e9"
ZWSP = "\u200b"


# ---------------------------------------------------------------------------------------
# 1. helper-vs-regex equivalence
# ---------------------------------------------------------------------------------------

_NEGATIVE_VERB_TABLE = [
    pytest.param("", False, id="empty"),
    pytest.param("run the nightly report", False, id="benign"),
    pytest.param("nothing to see here", False, id="no-needs-trailing-space"),
    pytest.param("say no to drugs", True, id="no-word"),
    pytest.param("piano keys", True, id="no-space-inside-a-word"),
    pytest.param("bypass the check", True, id="bypass-at-start"),
    pytest.param("then it was removed", True, id="remove-inside-removed"),
    pytest.param("please remov the file", False, id="truncated-remove"),
    pytest.param("dele te it", False, id="split-delete"),
    pytest.param("self approve it", False, id="self-approve-without-hyphen"),
    pytest.param("auto reject it", False, id="auto-reject-without-hyphen"),
    pytest.param("do it without asking", True, id="without"),
    pytest.param("deploy hiring model without review", True, id="long-phrase"),
    pytest.param("process customer pii now", True, id="phrase-with-spaces"),
    pytest.param(f"caf{E_ACUTE}, no thanks", True, id="non-ascii-with-hit"),
    pytest.param(f"caf{E_ACUTE} au lait", False, id="non-ascii-without-hit"),
    pytest.param(f"na\u00efve approach to {E_ACUTE}t\u00e9", False, id="non-ascii-clean"),
    pytest.param(f"{LONG_S}kip the step", True, id="long-s-folds-to-s"),
    pytest.param(f"d{DOTLESS_I}sable logging", True, id="dotless-i-folds-to-i"),
    pytest.param(f"sk{DOTLESS_I}p it", True, id="dotless-i-inside-skip"),
    pytest.param("\u4e2d\u6587 delete it", True, id="cjk-with-hit"),
    pytest.param("\u4e2d\u6587 only", False, id="cjk-clean"),
]


def _regex_says(text_lower: str) -> bool:
    return bool(_NEGATIVE_VERBS_RE.search(text_lower))


@pytest.mark.parametrize(("text", "expected"), _NEGATIVE_VERB_TABLE)
def test_negative_verb_helper_matches_regex_on_table(text: str, expected: bool) -> None:
    assert _regex_says(text) is expected  # the table itself agrees with the regex
    assert engine_core._has_negative_verb(text) is expected


@pytest.mark.parametrize("verb", _NEGATIVE_VERBS_LIST)
def test_negative_verb_helper_flags_every_listed_verb(verb: str) -> None:
    assert engine_core._has_negative_verb(f"please {verb} the records") is True


@pytest.mark.parametrize("verb", _NEGATIVE_VERBS_LIST)
@pytest.mark.parametrize("mangle", ["drop-last", "drop-first", "uppercased-then-lowered"])
def test_negative_verb_helper_equals_regex_on_mangled_listed_verbs(verb: str, mangle: str) -> None:
    mangled = {
        "drop-last": verb[:-1],
        "drop-first": verb[1:],
        "uppercased-then-lowered": verb.upper(),
    }[mangle]
    text = f"x {mangled} y".lower()
    assert engine_core._has_negative_verb(text) is _regex_says(text)


def _negative_verb_corpus(count: int = 3000, seed: int = 20240611) -> list[str]:
    rng = random.Random(seed)
    pieces = [
        *_NEGATIVE_VERBS_LIST,
        *(w[: len(w) // 2] for w in _NEGATIVE_VERBS_LIST),
        *(w[1:] for w in _NEGATIVE_VERBS_LIST),
        "a",
        "b",
        "n",
        "o",
        "no",
        "no ",
        " ",
        " ",
        "-",
        "1",
        LONG_S,
        DOTLESS_I,
        KELVIN,
        DOTTED_CAP_I,
        E_ACUTE,
        "\u00df",
        ZWSP,
    ]
    corpus = []
    for _ in range(count):
        raw = "".join(rng.choice(pieces) for _ in range(rng.randint(1, 8)))
        if rng.random() < 0.5:
            raw = "".join(c.upper() if rng.random() < 0.5 else c for c in raw)
        corpus.append(raw.lower())
    return corpus


def test_negative_verb_helper_equals_regex_on_seeded_random_corpus() -> None:
    mismatches = [
        text
        for text in _negative_verb_corpus()
        if engine_core._has_negative_verb(text) is not _regex_says(text)
    ]
    assert mismatches == []


def test_negative_verb_random_corpus_has_both_outcomes_and_non_ascii_text() -> None:
    corpus = _negative_verb_corpus()
    hits = sum(_regex_says(t) for t in corpus)
    non_ascii = sum(not t.isascii() for t in corpus)
    non_ascii_hits = sum(_regex_says(t) for t in corpus if not t.isascii())
    assert min(hits, len(corpus) - hits, non_ascii, non_ascii_hits) >= 200


def test_negative_verb_literals_cover_every_listed_verb_without_redundancy() -> None:
    literals = engine_core._negative_verb_literals()
    assert literals is not None
    every_verb_contains_a_literal = all(
        any(lit in verb for lit in literals) for verb in _NEGATIVE_VERBS_LIST
    )
    no_literal_contains_another = not any(a != b and a in b for a in literals for b in literals)
    assert (every_verb_contains_a_literal, no_literal_contains_another) == (True, True)


_HIDDEN_ASCII_CONTROLS = (
    frozenset(range(0x00, 0x09)) | {0x0B, 0x0C} | frozenset(range(0x0E, 0x20)) | {0x7F}
)


def _plain_ascii_oracle(text: str) -> bool:
    return all(ord(c) < 0x80 and ord(c) not in _HIDDEN_ASCII_CONTROLS for c in text)


_PLAIN_ASCII_TABLE = [
    pytest.param("", True, id="empty"),
    pytest.param("hello world", True, id="printable"),
    pytest.param("~!@#$%^&*()_+{}|:\"<>?`-=[]\\;',./ 09azAZ", True, id="all-punctuation"),
    pytest.param("line one\nline two\r\n\tindented", True, id="tab-newline-cr-allowed"),
    pytest.param("del\x00ete", False, id="nul"),
    pytest.param("a\x07b", False, id="bell"),
    pytest.param("a\x0bb", False, id="vertical-tab"),
    pytest.param("a\x0cb", False, id="form-feed"),
    pytest.param("a\x1fb", False, id="unit-separator"),
    pytest.param("a\x7fb", False, id="del"),
    pytest.param("ok\x00", False, id="control-at-end"),
    pytest.param("\x00ok", False, id="control-at-start"),
    pytest.param(f"caf{E_ACUTE}", False, id="latin1"),
    pytest.param("\uff44\uff45\uff4c", False, id="fullwidth"),
    pytest.param(f"a{ZWSP}b", False, id="zero-width-space"),
    pytest.param("a\x80b", False, id="c1-control"),
    pytest.param("\u4e2d\u6587", False, id="cjk"),
]


@pytest.mark.parametrize(("text", "expected"), _PLAIN_ASCII_TABLE)
def test_is_plain_ascii_table(text: str, expected: bool) -> None:
    assert engine_core._is_plain_ascii(text) is expected


@pytest.mark.parametrize("codepoint", range(0x0, 0x300))
def test_is_plain_ascii_decides_every_codepoint_up_to_0x2ff(codepoint: int) -> None:
    text = f"a{chr(codepoint)}b"
    assert engine_core._is_plain_ascii(text) is _plain_ascii_oracle(text)


def test_is_plain_ascii_equals_oracle_on_seeded_random_corpus() -> None:
    rng = random.Random(7)
    alphabet = [chr(c) for c in range(0x80)] + [E_ACUTE, ZWSP, KELVIN, "\u4e2d", "\x80", "\xa0"]
    texts = ["".join(rng.choice(alphabet) for _ in range(rng.randint(0, 6))) for _ in range(3000)]
    mismatches = [t for t in texts if engine_core._is_plain_ascii(t) is not _plain_ascii_oracle(t)]
    assert mismatches == []


# ---------------------------------------------------------------------------------------
# 2. required-literal derivation
# ---------------------------------------------------------------------------------------

# (pattern, expected literal or None to skip the exact check, lowered-ASCII sample texts).
# An empty sample tuple means no lowered text can match (the soundness check is vacuous).
_GATE_ROWS: list[tuple[str, str | None, tuple[str, ...]]] = [
    ("delete", "delete", ("delete", "please delete it")),
    ("FOO", "foo", ("foo",)),
    ("a", "a", ("a", "xax")),
    ("", "", ("", "anything")),
    # alternation: no literal is required by every branch
    ("foo|bar", "", ("foo", "bar", "xbarx")),
    ("a|b", "", ("a", "b")),
    ("foobar|foobaz", None, ("foobar", "foobaz")),
    # optional pieces end the run and are never part of it
    ("foo(bar)?", "foo", ("foo", "foobar")),
    ("(?:foo)?bar", "bar", ("bar", "foobar")),
    ("foobar?", "fooba", ("fooba", "foobar")),
    ("x*foo", "foo", ("foo", "xxfoo")),
    ("foo.*bar", None, ("foobar", "foo and bar")),
    # counted repeats, including zero
    ("ab{0,2}cd", "cd", ("acd", "abcd", "abbcd")),
    ("ab{0}cd", "cd", ("acd",)),
    ("(ab){0}cd", "cd", ("cd",)),
    ("ab{1,3}cd", "cd", ("abcd", "abbbcd")),
    ("abc{0}", "ab", ("ab", "abc")),
    ("(foo)+bar", "bar", ("foobar", "foofoobar")),
    # lookarounds consume nothing and are never required text
    ("(?<=foo)bar", "bar", ("foobar",)),
    ("(?<!foo)bar", "bar", ("xbar", "bar", "foobar")),
    ("foo(?!bar)", "foo", ("foo", "foobaz", "foobar")),
    # scoped inline flags are not entered
    ("(?-i:foo)bar", "bar", ("foobar",)),
    ("(?-i:Foo)bar", "bar", ()),
    ("(?-i:foobar)baz", "baz", ("foobarbaz",)),
    ("(?i:foo)bar", "bar", ("foobar",)),
    # plain groups are entered, because their items match in sequence exactly once
    ("(?:foo)bar", "foobar", ("foobar",)),
    ("(foo)bar", "foobar", ("foobar",)),
    ("(?P<word>foo)bar", "foobar", ("foobar",)),
    ("((foo))bar", "foobar", ("foobar",)),
    ("(?:foo|bar)baz", "baz", ("foobaz", "barbaz")),
    ("x(?:foo|bar)baz", "baz", ("xfoobaz",)),
    ("(foo)\\1bar", None, ("foofoobar",)),
    # non-ASCII literals in the pattern end the run (fold-unsafe letters are fine in ASCII text)
    (f"{LONG_S}ecret", "ecret", ("secret",)),
    (f"{KELVIN}ill", "ill", ("kill",)),
    ("\\u212aill", "ill", ("kill",)),
    (f"d{DOTLESS_I}sable", "sable", ("disable",)),
    ("skip", "skip", ("skip", "please skip it")),
    # escapes
    ("a\\x2db", "a-b", ("a-b",)),
    ("a\\x2Db", "a-b", ("a-b",)),
    ("a\\.b", "a.b", ("a.b",)),
    ("a\\nb", "a\nb", ("a\nb",)),
    ("\\d+foo", "foo", ("1foo", "123foo")),
    ("\\bfoo\\b", "foo", ("foo", "a foo b")),
    ("[a]bc", "abc", ("abc",)),
    ("[ab]cd", "cd", ("acd", "bcd")),
    ("a{0}", "", ("", "a")),
    (".", "", ("x",)),
    ("(?#note)foo", "foo", ("foo",)),
    ("(?s)abc", "abc", ("abc",)),
    ("disable\\s+audit", "disable", ("disable audit", "disable   audit")),
    ("\\b\\d{3}-\\d{2}-\\d{4}\\b", "-", ("123-45-6789",)),
    ("sk-[a-z0-9]{8,}", "sk-", ("sk-abcdefgh12",)),
]

_GATE_IDS = [ascii(row[0]) for row in _GATE_ROWS]
_EXACT_GATE_ROWS = [row for row in _GATE_ROWS if row[1] is not None]


def _gate_corpus(pattern: str, samples: Iterable[str]) -> list[str]:
    rng = random.Random(pattern)
    alphabet = sorted({c for c in pattern.lower() if c.isascii() and c.isalnum()} | set(" -.x\n"))
    texts = []
    for sample in samples:
        texts += [sample, f"x{sample}", f"{sample}x", f"{sample} {sample}"]
    texts += ["".join(rng.choice(alphabet) for _ in range(rng.randint(0, 14))) for _ in range(250)]
    return texts


@pytest.mark.parametrize(("pattern", "expected", "_samples"), _EXACT_GATE_ROWS)
def test_gate_literal_for_pattern(pattern: str, expected: str, _samples: tuple[str, ...]) -> None:
    assert engine_core._ascii_gate_literal_of(pattern, _COMPILE_FLAGS) == expected


@pytest.mark.parametrize(("pattern", "expected", "_samples"), _EXACT_GATE_ROWS)
def test_gate_literal_of_compiled_pattern_matches_source_derivation(
    pattern: str, expected: str, _samples: tuple[str, ...]
) -> None:
    compiled = re.compile(pattern, re.IGNORECASE)
    assert engine_core._ascii_gate_literal(compiled) == expected


@pytest.mark.parametrize(("pattern", "_expected", "samples"), _GATE_ROWS, ids=_GATE_IDS)
def test_text_lacking_gate_literal_never_matches_the_regex(
    pattern: str, _expected: str | None, samples: tuple[str, ...]
) -> None:
    compiled = re.compile(pattern, re.IGNORECASE)
    gate = engine_core._ascii_gate_literal(compiled)
    escapes = [
        text
        for text in _gate_corpus(pattern, samples)
        if gate not in text and compiled.search(text) is not None
    ]
    assert escapes == []


@pytest.mark.parametrize(
    ("pattern", "_expected", "samples"),
    [row for row in _GATE_ROWS if row[2]],
    ids=[ascii(row[0]) for row in _GATE_ROWS if row[2]],
)
def test_gate_corpus_contains_texts_the_regex_matches(
    pattern: str, _expected: str | None, samples: tuple[str, ...]
) -> None:
    compiled = re.compile(pattern, re.IGNORECASE)
    assert any(compiled.search(text) for text in _gate_corpus(pattern, samples))


@pytest.mark.parametrize(
    ("pattern", "samples"),
    [(row[0], row[2]) for row in _GATE_ROWS if row[1] and row[2]],
    ids=[ascii(row[0]) for row in _GATE_ROWS if row[1] and row[2]],
)
def test_gate_corpus_contains_matching_texts_that_hold_the_literal(
    pattern: str, samples: tuple[str, ...]
) -> None:
    compiled = re.compile(pattern, re.IGNORECASE)
    gate = engine_core._ascii_gate_literal(compiled)
    matching = [t for t in _gate_corpus(pattern, samples) if compiled.search(t)]
    assert matching
    assert all(gate in text for text in matching)


def test_gate_literal_is_empty_when_pattern_is_not_ignorecase() -> None:
    assert engine_core._ascii_gate_literal(re.compile("delete")) == ""


@pytest.mark.parametrize("flags", [0, re.UNICODE, re.MULTILINE | re.UNICODE, re.DOTALL])
def test_gate_literal_is_empty_for_every_flag_set_without_ignorecase(flags: int) -> None:
    assert engine_core._ascii_gate_literal_of("delete", flags) == ""


@pytest.mark.parametrize("pattern", ["(", "[a-", "a{2,1}", "(?P<1>x)", "*abc"])
def test_gate_literal_is_empty_when_the_parser_rejects_the_pattern(pattern: str) -> None:
    with pytest.raises(re.error):
        re.compile(pattern, re.IGNORECASE)
    assert engine_core._ascii_gate_literal_of(pattern, _COMPILE_FLAGS) == ""


_NEW_SYNTAX_ROWS = [
    pytest.param("(?>foo)bar", "bar", ("foobar",), id="atomic-group"),
    pytest.param("(?>foo|bar)baz", "baz", ("foobaz", "barbaz"), id="atomic-alternation"),
    pytest.param("fooa++barbaz", "barbaz", ("fooaabarbaz",), id="possessive-plus"),
    pytest.param("foo[ab]*+barbaz", "barbaz", ("foobarbaz", "fooabbarbaz"), id="possessive-star"),
    pytest.param(
        "foo(?:ab)?+barbaz", "barbaz", ("foobarbaz", "fooabbarbaz"), id="possessive-optional"
    ),
]


@pytest.mark.skipif(sys.version_info < (3, 11), reason="atomic groups and possessive need 3.11+")
@pytest.mark.parametrize(("pattern", "expected", "samples"), _NEW_SYNTAX_ROWS)
def test_gate_literal_for_atomic_groups_and_possessive_quantifiers(
    pattern: str, expected: str, samples: tuple[str, ...]
) -> None:
    compiled = re.compile(pattern, re.IGNORECASE)
    assert engine_core._ascii_gate_literal(compiled) == expected


@pytest.mark.skipif(sys.version_info < (3, 11), reason="atomic groups and possessive need 3.11+")
@pytest.mark.parametrize(("pattern", "_expected", "samples"), _NEW_SYNTAX_ROWS)
def test_text_lacking_gate_literal_never_matches_atomic_or_possessive_regex(
    pattern: str, _expected: str, samples: tuple[str, ...]
) -> None:
    compiled = re.compile(pattern, re.IGNORECASE)
    gate = engine_core._ascii_gate_literal(compiled)
    escapes = [
        text
        for text in _gate_corpus(pattern, samples)
        if gate not in text and compiled.search(text) is not None
    ]
    assert escapes == []


@pytest.mark.skipif(sys.version_info >= (3, 11), reason="3.10 rejects the newer syntax")
@pytest.mark.parametrize(
    "pattern", [row.values[0] for row in _NEW_SYNTAX_ROWS], ids=[r.id for r in _NEW_SYNTAX_ROWS]
)
def test_gate_literal_is_empty_for_syntax_the_running_python_rejects(pattern: str) -> None:
    with pytest.raises(re.error):
        re.compile(pattern, re.IGNORECASE)
    assert engine_core._ascii_gate_literal_of(pattern, _COMPILE_FLAGS) == ""


@pytest.mark.parametrize("ignorecase_first", [True, False])
def test_gate_literal_cache_keeps_same_source_apart_per_flags(ignorecase_first: bool) -> None:
    pattern = f"cachekey{'a' if ignorecase_first else 'b'}marker"
    calls = [_COMPILE_FLAGS, re.UNICODE] if ignorecase_first else [re.UNICODE, _COMPILE_FLAGS]
    results = {flags: engine_core._ascii_gate_literal_of(pattern, flags) for flags in calls}
    assert results == {_COMPILE_FLAGS: pattern.lower(), re.UNICODE: ""}


@pytest.mark.parametrize(("pattern", "_expected", "_samples"), _GATE_ROWS, ids=_GATE_IDS)
def test_gate_literal_cache_returns_what_a_fresh_derivation_returns(
    pattern: str, _expected: str | None, _samples: tuple[str, ...]
) -> None:
    derive = engine_core._ascii_gate_literal_of
    uncached = getattr(derive, "__wrapped__", None)
    first = derive(pattern, _COMPILE_FLAGS)
    again = derive(pattern, _COMPILE_FLAGS)
    assert uncached is not None
    assert first == again == uncached(pattern, _COMPILE_FLAGS)


def _cache_hits(function: Any) -> int:
    cache_info = getattr(function, "cache_info", None)
    return -1 if cache_info is None else int(cache_info().hits)


def test_gate_literal_derivation_is_served_from_the_cache_on_repeat() -> None:
    derive = engine_core._ascii_gate_literal_of
    pattern = "cache-hit-probe-pattern"
    derive(pattern, _COMPILE_FLAGS)
    hits_before = _cache_hits(derive)
    derive(pattern, _COMPILE_FLAGS)
    assert _cache_hits(derive) == hits_before + 1 >= 1


# ---------------------------------------------------------------------------------------
# 3. engine-level behaviour through GovernanceEngine.validate
# ---------------------------------------------------------------------------------------

_LENGTHS = (20, 63, 64, 65, 200)  # around the 64-character keyword-gate threshold
_LONG_LENGTHS = (40, 63, 64, 65, 200)  # long enough for the longest near-miss snippets
_WHERE = ("start", "middle", "end")
_PREFIXES = ("", "run ")  # "run " is a constructive verb: selects the positive-verb scan mode
_FILLER_WORDS = "lorem ipsum dolor sit amet consectetur adipiscing elit sed tempor "
_NON_ASCII_FILLER_WORDS = f"{E_ACUTE}l{E_ACUTE}phant caf{E_ACUTE} na\u00efve \u00fcber \u00e0 "


def _fill(count: int, words: str = _FILLER_WORDS) -> str:
    return (words * (count // len(words) + 1))[:count]


def _place(snippet: str, length: int, where: str, words: str = _FILLER_WORDS) -> str:
    """Return text of exactly ``length`` characters with ``snippet`` at the given spot."""
    pad = length - len(snippet)
    assert pad >= 2, "snippet too long for the requested length"
    if where == "start":
        text = f"{snippet} {_fill(pad - 1, words)}"
    elif where == "end":
        text = f"{_fill(pad - 1, words)} {snippet}"
    else:
        left = (pad - 2) // 2
        text = f"{_fill(left, words)} {snippet} {_fill(pad - 2 - left, words)}"
    assert len(text) == length
    return text


def _text(prefix: str, snippet: str, length: int, where: str, words: str = _FILLER_WORDS) -> str:
    return prefix + _place(snippet, length - len(prefix), where, words)


def _clean_text(prefix: str, length: int, words: str = _FILLER_WORDS) -> str:
    return prefix + _fill(length - len(prefix), words)


def _rule(rule_id: str, **kwargs: Any) -> Rule:
    return Rule(id=rule_id, text=f"rule {rule_id}", severity=Severity.HIGH, **kwargs)


def _build_engine(rules: list[Rule]) -> GovernanceEngine:
    constitution = Constitution.from_rules(rules, name="scan-shortcuts")
    return GovernanceEngine(constitution, strict=False, freeze_gc=False)


def _verdict(engine: GovernanceEngine, text: str, **kwargs: Any) -> tuple[bool, frozenset[str]]:
    result = engine.validate(text, **kwargs)
    return result.valid, frozenset(v.rule_id for v in result.violations)


@functools.cache
def _pattern_engine() -> GovernanceEngine:
    return _build_engine(
        [
            _rule("DROP-TABLE", patterns=[r"drop\s+table"]),
            _rule("DISABLE-AUDIT", patterns=[r"disable\s+audit"]),
            _rule("API-KEY", patterns=[r"sk-[a-z0-9]{8,}"]),  # no anchor word: the gate decides
        ]
    )


@functools.cache
def _mixed_engine() -> GovernanceEngine:
    return _build_engine(
        [
            _rule("PASSWORD", keywords=["password"]),  # a "negative" keyword
            _rule("EXFIL", keywords=["exfiltrate"]),  # not a negative keyword
            _rule("DROP-TABLE", patterns=[r"drop\s+table"]),
            _rule("AUDIT-LOG", patterns=[r"audit\s+log"]),
        ]
    )


@functools.cache
def _keyword_engine() -> GovernanceEngine:
    return _build_engine(
        [_rule("PASSWORD", keywords=["password"]), _rule("EXFIL", keywords=["exfiltrate"])]
    )


_ENGINES = {"pattern-only": _pattern_engine, "keywords-and-pattern": _mixed_engine}


def test_filler_texts_contain_no_negative_verb_and_no_rule_trigger() -> None:
    texts = [_fill(500), _fill(500, _NON_ASCII_FILLER_WORDS)]
    triggers = ("password", "exfiltrate", "drop", "table", "disable", "audit")
    assert [
        t for t in texts if _regex_says(t.lower()) or any(w in t.lower() for w in triggers)
    ] == []


@requires_python_regex_backend
class TestPatternRuleAcrossThreshold:
    @pytest.mark.parametrize("where", _WHERE)
    @pytest.mark.parametrize("length", _LENGTHS)
    @pytest.mark.parametrize("prefix", _PREFIXES, ids=["plain", "constructive-verb"])
    @pytest.mark.parametrize("engine_name", list(_ENGINES))
    def test_pattern_match_is_denied(
        self, engine_name: str, prefix: str, length: int, where: str
    ) -> None:
        text = _text(prefix, "drop table", length, where)
        assert _verdict(_ENGINES[engine_name](), text) == (False, frozenset({"DROP-TABLE"}))

    @pytest.mark.parametrize("length", _LENGTHS)
    @pytest.mark.parametrize("prefix", _PREFIXES, ids=["plain", "constructive-verb"])
    @pytest.mark.parametrize("engine_name", list(_ENGINES))
    def test_clean_text_is_allowed(self, engine_name: str, prefix: str, length: int) -> None:
        text = _clean_text(prefix, length)
        assert _verdict(_ENGINES[engine_name](), text) == (True, frozenset())

    @pytest.mark.parametrize("length", _LENGTHS)
    @pytest.mark.parametrize("prefix", _PREFIXES, ids=["plain", "constructive-verb"])
    def test_text_holding_the_gate_literal_but_not_the_pattern_is_allowed(
        self, prefix: str, length: int
    ) -> None:
        # "table" is the gate literal; "drop ... table" with a word between is not a match.
        text = _text(prefix, "drop the table", length, "middle")
        assert _verdict(_pattern_engine(), text) == (True, frozenset())

    @pytest.mark.parametrize("where", _WHERE)
    @pytest.mark.parametrize("length", _LENGTHS)
    def test_two_pattern_rules_in_one_text_both_fire(self, length: int, where: str) -> None:
        text = _text("", "drop table and disable audit", length + 20, where)
        assert _verdict(_pattern_engine(), text) == (
            False,
            frozenset({"DROP-TABLE", "DISABLE-AUDIT"}),
        )

    @pytest.mark.parametrize("prefix", _PREFIXES, ids=["plain", "constructive-verb"])
    @pytest.mark.parametrize("length", _LENGTHS)
    def test_keyword_and_pattern_hit_in_one_text_both_fire(self, prefix: str, length: int) -> None:
        text = _text(prefix, "password drop table", length + 20, "middle")
        assert _verdict(_mixed_engine(), text) == (False, frozenset({"PASSWORD", "DROP-TABLE"}))

    @pytest.mark.parametrize("snippet", ["DROP TABLE", "Drop Table", "dRoP\tTaBlE", "drop\n table"])
    @pytest.mark.parametrize("length", _LENGTHS)
    def test_mixed_case_and_whitespace_variants_are_denied(self, snippet: str, length: int) -> None:
        text = _text("", snippet, length, "end")
        assert _verdict(_pattern_engine(), text) == (False, frozenset({"DROP-TABLE"}))

    @pytest.mark.parametrize("where", _WHERE)
    @pytest.mark.parametrize("length", _LENGTHS)
    def test_match_in_non_ascii_text_is_denied(self, length: int, where: str) -> None:
        text = _text("", "drop table", length, where, _NON_ASCII_FILLER_WORDS)
        assert _verdict(_pattern_engine(), text) == (False, frozenset({"DROP-TABLE"}))

    @pytest.mark.parametrize("length", _LENGTHS)
    def test_non_ascii_clean_text_is_allowed(self, length: int) -> None:
        text = _clean_text("", length, _NON_ASCII_FILLER_WORDS)
        assert _verdict(_pattern_engine(), text) == (True, frozenset())

    @pytest.mark.parametrize("where", _WHERE)
    @pytest.mark.parametrize("length", _LENGTHS)
    def test_match_through_a_case_fold_the_normalizer_keeps_is_denied(
        self, length: int, where: str
    ) -> None:
        # Dotless i is folded to i by IGNORECASE but left alone by NFKC, so the gate literal
        # "disable" is absent from the lowered text while the regex still matches.
        text = _text("", f"d{DOTLESS_I}sable audit", length, where)
        assert _verdict(_pattern_engine(), text) == (False, frozenset({"DISABLE-AUDIT"}))

    @pytest.mark.parametrize("where", _WHERE)
    @pytest.mark.parametrize("length", _LENGTHS)
    @pytest.mark.parametrize("prefix", _PREFIXES, ids=["plain", "constructive-verb"])
    def test_pattern_without_an_anchor_word_is_denied(
        self, prefix: str, length: int, where: str
    ) -> None:
        text = _text(prefix, "sk-abcdefgh12", length, where)
        assert _verdict(_pattern_engine(), text) == (False, frozenset({"API-KEY"}))

    @pytest.mark.parametrize("where", _WHERE)
    @pytest.mark.parametrize("length", _LENGTHS)
    def test_pattern_without_an_anchor_word_is_denied_in_non_ascii_text(
        self, length: int, where: str
    ) -> None:
        text = _text("", "SK-ABCDEFGH12", length, where, _NON_ASCII_FILLER_WORDS)
        assert _verdict(_pattern_engine(), text) == (False, frozenset({"API-KEY"}))

    @pytest.mark.parametrize("length", _LENGTHS)
    def test_near_miss_for_a_pattern_without_an_anchor_word_is_allowed(self, length: int) -> None:
        text = _text("", "sk-abc sk_abcdefgh12 s-k-abcdefgh12", length + 30, "middle")
        assert _verdict(_pattern_engine(), text) == (True, frozenset())

    @pytest.mark.parametrize("length", _LENGTHS)
    def test_look_alike_without_the_fold_is_allowed(self, length: int) -> None:
        text = _text("", f"d{DOTLESS_I}sabl audit", length, "middle")
        assert _verdict(_pattern_engine(), text) == (True, frozenset())

    @pytest.mark.parametrize("snippet", ["dro\x00p table", "drop\x07 table", "drop tab\x7fle"])
    def test_ascii_control_characters_inside_a_match_are_stripped_and_denied(
        self, snippet: str
    ) -> None:
        text = _text("", snippet, 100, "middle")
        assert _verdict(_pattern_engine(), text) == (False, frozenset({"DROP-TABLE"}))

    def test_tabs_and_newlines_in_clean_text_are_allowed(self) -> None:
        text = "lorem\tipsum\ndolor\r\nsit amet " * 5
        assert _verdict(_pattern_engine(), text) == (True, frozenset())


@requires_python_regex_backend
class TestKeywordRuleAcrossThreshold:
    @pytest.mark.parametrize("where", _WHERE)
    @pytest.mark.parametrize("length", _LENGTHS)
    @pytest.mark.parametrize(
        ("prefix", "keyword", "rule_id"),
        [
            pytest.param("", "password", "PASSWORD", id="negative-keyword"),
            pytest.param("", "exfiltrate", "EXFIL", id="non-negative-keyword"),
            pytest.param("run ", "password", "PASSWORD", id="negative-keyword-after-verb"),
        ],
    )
    def test_keyword_is_denied(
        self, prefix: str, keyword: str, rule_id: str, length: int, where: str
    ) -> None:
        text = _text(prefix, keyword, length, where)
        assert _verdict(_keyword_engine(), text) == (False, frozenset({rule_id}))

    @pytest.mark.parametrize("length", _LENGTHS)
    @pytest.mark.parametrize("prefix", _PREFIXES, ids=["plain", "constructive-verb"])
    def test_clean_text_is_allowed(self, prefix: str, length: int) -> None:
        assert _verdict(_keyword_engine(), _clean_text(prefix, length)) == (True, frozenset())

    @pytest.mark.parametrize("length", _LONG_LENGTHS)
    @pytest.mark.parametrize("prefix", _PREFIXES, ids=["plain", "constructive-verb"])
    def test_near_miss_keywords_are_allowed(self, prefix: str, length: int) -> None:
        text = _text(prefix, "passwor exfiltrat pass word", length, "middle")
        assert _verdict(_keyword_engine(), text) == (True, frozenset())

    @pytest.mark.parametrize("snippet", ["PASSWORD", "Password", "pAsSwOrD"])
    @pytest.mark.parametrize("length", _LENGTHS)
    def test_mixed_case_keyword_is_denied(self, snippet: str, length: int) -> None:
        text = _text("", snippet, length, "middle")
        assert _verdict(_keyword_engine(), text) == (False, frozenset({"PASSWORD"}))

    @pytest.mark.parametrize("keyword", ["password", "exfiltrate"])
    @pytest.mark.parametrize("where", _WHERE)
    @pytest.mark.parametrize("length", _LENGTHS)
    def test_keyword_in_non_ascii_text_is_denied(
        self, keyword: str, length: int, where: str
    ) -> None:
        text = _text("", keyword, length, where, _NON_ASCII_FILLER_WORDS)
        assert _verdict(_keyword_engine(), text)[0] is False

    @pytest.mark.parametrize("length", _LENGTHS)
    def test_non_ascii_clean_text_is_allowed(self, length: int) -> None:
        text = _clean_text("", length, _NON_ASCII_FILLER_WORDS)
        assert _verdict(_keyword_engine(), text) == (True, frozenset())

    @pytest.mark.parametrize("snippet", ["ex\x00filtrate", "pass\x07word", "exfil\x7ftrate"])
    def test_ascii_control_characters_inside_a_keyword_are_stripped_and_denied(
        self, snippet: str
    ) -> None:
        text = _text("", snippet, 100, "middle")
        assert _verdict(_keyword_engine(), text)[0] is False

    def test_both_keywords_in_one_long_text_fire_both_rules(self) -> None:
        text = _text("", "password and exfiltrate", 120, "middle")
        assert _verdict(_keyword_engine(), text) == (False, frozenset({"PASSWORD", "EXFIL"}))


@requires_python_regex_backend
class TestCaseFoldMatchOnEveryScanPath:
    """Dotless i keeps the gate literal out of the text but not the regex match."""

    @pytest.mark.parametrize("length", [63, 64, 65, 200])
    @pytest.mark.parametrize("where", _WHERE)
    @pytest.mark.parametrize("with_keyword", [False, True], ids=["pattern-only", "keyword-too"])
    @pytest.mark.parametrize("prefix", _PREFIXES, ids=["plain", "constructive-verb"])
    def test_pattern_match_through_the_fold_is_denied(
        self, prefix: str, with_keyword: bool, where: str, length: int
    ) -> None:
        snippet = f"aud{DOTLESS_I}t log" + (" password" if with_keyword else "")
        expected = {"AUDIT-LOG"} | ({"PASSWORD"} if with_keyword else set())
        text = _text(prefix, snippet, length, where)
        assert _verdict(_mixed_engine(), text) == (False, frozenset(expected))

    @pytest.mark.parametrize("with_keyword", [False, True], ids=["pattern-only", "keyword-too"])
    @pytest.mark.parametrize("prefix", _PREFIXES, ids=["plain", "constructive-verb"])
    def test_look_alike_without_the_fold_is_allowed_on_every_path(
        self, prefix: str, with_keyword: bool
    ) -> None:
        snippet = f"aud{DOTLESS_I}t lag" + (" passwor" if with_keyword else "")
        text = _text(prefix, snippet, 100, "middle")
        assert _verdict(_mixed_engine(), text) == (True, frozenset())


@requires_python_regex_backend
class TestContextDetailText:
    """``action_detail`` / ``action_description`` values are scanned with the same shortcuts."""

    @pytest.mark.parametrize("key", ["action_detail", "action_description"])
    @pytest.mark.parametrize("where", _WHERE)
    @pytest.mark.parametrize("length", _LENGTHS)
    def test_keyword_in_detail_text_is_denied_on_the_hot_path(
        self, length: int, where: str, key: str
    ) -> None:
        detail = _text("", "exfiltrate", length, where)
        assert _verdict(_keyword_engine(), "harmless note", context={key: detail}) == (
            False,
            frozenset({"EXFIL"}),
        )

    @pytest.mark.parametrize("key", ["action_detail", "action_description"])
    @pytest.mark.parametrize("length", _LENGTHS)
    def test_clean_detail_text_is_allowed_on_the_hot_path(self, length: int, key: str) -> None:
        context = {key: _clean_text("", length)}
        assert _verdict(_keyword_engine(), "harmless note", context=context) == (
            True,
            frozenset(),
        )

    @pytest.mark.parametrize("length", _LENGTHS)
    def test_non_string_and_other_context_values_are_not_scanned(self, length: int) -> None:
        context = {"action_detail": 12345, "note": _text("", "exfiltrate", length, "middle")}
        assert _verdict(_keyword_engine(), "harmless note", context=context) == (
            True,
            frozenset(),
        )

    @pytest.mark.parametrize("length", _LENGTHS)
    def test_keyword_in_detail_text_is_denied_on_the_runtime_filtering_path(
        self, length: int
    ) -> None:
        engine, _ = _runtime_engine(_plain_rules())
        context = {"action_detail": _text("", "wipe disk", length, "middle")}
        assert _verdict(engine, "harmless note", context=context) == (
            False,
            frozenset({"ALWAYS"}),
        )

    @pytest.mark.parametrize("length", _LENGTHS)
    def test_clean_detail_text_is_allowed_on_the_runtime_filtering_path(self, length: int) -> None:
        engine, _ = _runtime_engine(_plain_rules())
        context = {"action_detail": _clean_text("", length)}
        assert _verdict(engine, "harmless note", context=context) == (True, frozenset())


@requires_python_regex_backend
class TestValidationResultFields:
    """The runtime-filtering result is built positionally; a swapped field would corrupt it."""

    @staticmethod
    def _engine(**kwargs: Any) -> tuple[GovernanceEngine, Constitution]:
        constitution = Constitution.from_rules(
            [
                _rule("PASSWORD", keywords=["password"]),
                _rule("DROP-TABLE", patterns=["drop table"]),
                # A deprecated rule routes validate() through the runtime-filtering path.
                _rule("RETIRED", keywords=["zzretired"], deprecated=True),
            ],
            name="result-fields",
        )
        return GovernanceEngine(constitution, strict=False, freeze_gc=False, **kwargs), constitution

    @pytest.mark.parametrize("audit_log", [None, AuditLog()], ids=["fast-audit", "full-audit"])
    def test_denied_result_carries_every_field_in_its_own_slot(
        self, audit_log: AuditLog | None
    ) -> None:
        engine, constitution = self._engine(audit_log=audit_log)
        action = "please drop table users and show the password"
        result = engine.validate(action, agent_id="agent-7")
        assert (
            result.valid,
            result.constitutional_hash,
            sorted(v.rule_id for v in result.violations),
            result.rules_checked,
            result.action,
            result.agent_id,
            result.warnings,
        ) == (
            False,
            constitution.hash,
            ["DROP-TABLE", "PASSWORD"],
            2,
            action,
            "agent-7",
            [],
        )

    @pytest.mark.parametrize("audit_log", [None, AuditLog()], ids=["fast-audit", "full-audit"])
    def test_result_metadata_fields_are_well_formed(self, audit_log: AuditLog | None) -> None:
        engine, _ = self._engine(audit_log=audit_log)
        result = engine.validate("drop table users")
        assert (
            result.latency_ms >= 0.0,
            result.request_id.isdigit(),
            bool(re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", result.timestamp)),
            result.action_taken is not None,
        ) == (True, True, True, True)

    def test_matched_content_is_the_original_action_trimmed_to_200_characters(self) -> None:
        engine, _ = self._engine()
        action = "drop table " + "x" * 400
        result = engine.validate(action)
        assert [v.matched_content for v in result.violations] == [action[:200]]

    def test_full_audit_mode_records_the_denied_decision(self) -> None:
        audit = AuditLog()
        engine, _ = self._engine(audit_log=audit)
        engine.validate("drop table users", agent_id="agent-9")
        assert [(e.agent_id, e.valid) for e in audit.entries] == [("agent-9", False)]

    def test_full_and_fast_audit_modes_reach_the_same_verdict(self) -> None:
        fast, _ = self._engine()
        full, _ = self._engine(audit_log=AuditLog())
        texts = ["drop table x", "show the password", "nothing to see", _fill(200)]
        assert [_verdict(full, t) for t in texts] == [_verdict(fast, t) for t in texts]


# -- differential run against the rule-level reference ----------------------------------

_FUZZ_FILLER = [
    "lorem",
    "ipsum",
    "dolor",
    "quarterly",
    "budget",
    "weather",
    "sit",
    "amet",
    f"caf{E_ACUTE}",
    "na\u00efve",
    "\u00fcber",
    "\u4e2d\u6587",
    "1",
    "-",
]
_FUZZ_HITS = [
    "exfiltrate",
    "EXFILTRATE",
    "wipe disk",
    "drop table",
    "drop  table",
    "drop\ttable",
    "Drop Table",
    "disable audit",
    f"d{DOTLESS_I}sable audit",
    "123-45-6789",
    "sk-abcdefgh12",
    f"{LONG_S}k-abcdefgh12",
    "dro\x00p table",
    f"ex{ZWSP}filtrate",
    "\uff45xfiltrate",
]
_FUZZ_NEAR_MISSES = [
    "drop",
    "table",
    "disable",
    "wipe",
    "disk",
    "exfiltrat",
    "sk-",
    "123-45",
    "ssn",
]


@functools.cache
def _fuzz_rules() -> tuple[Rule, ...]:
    return (
        _rule("EXFIL", keywords=["exfiltrate"]),
        _rule("WIPE", keywords=["wipe disk"]),
        _rule("DROP-TABLE", patterns=[r"drop\s+table"]),
        _rule("DISABLE-AUDIT", patterns=[r"disable\s+audit"]),
        _rule("SSN", patterns=[r"\b\d{3}-\d{2}-\d{4}\b"]),
        _rule("API-KEY", patterns=[r"sk-[a-z0-9]{8,}"]),
    )


def _has_constructive_verb(text: str) -> bool:
    return any(
        w in _POSITIVE_VERBS_SET
        for variant in (text.lower(), normalize_for_matching(text).lower())
        for w in variant.split()[:4]
    )


def _fuzz_texts(count: int = 2500, seed: int = 1234) -> list[str]:
    """Seeded texts without a constructive verb up front, where hot path and rule agree."""
    rng = random.Random(seed)
    texts: list[str] = []
    while len(texts) < count:
        parts = [
            rng.choice(_FUZZ_HITS if rng.random() < 0.25 else _FUZZ_FILLER + _FUZZ_NEAR_MISSES)
            for _ in range(rng.randint(1, 16))
        ]
        text = " ".join(parts)
        if rng.random() < 0.5:  # pad to a length close to the keyword-gate threshold
            text += " " + _fill(max(0, rng.randint(58, 70) - len(text) - 1))
        if rng.random() < 0.3:
            text = text.upper() if rng.random() < 0.5 else text.title()
        if not _has_constructive_verb(text):
            texts.append(text)
    return texts


def _reference_verdict(text: str) -> frozenset[str]:
    normalized = normalize_for_matching(text)
    return frozenset(r.id for r in _fuzz_rules() if r.matches(text) or r.matches(normalized))


@requires_python_regex_backend
def test_engine_verdicts_equal_the_rule_level_reference_on_seeded_random_texts() -> None:
    engine = _build_engine(list(_fuzz_rules()))
    mismatches = [
        text for text in _fuzz_texts() if _verdict(engine, text)[1] != _reference_verdict(text)
    ]
    assert mismatches == []


@requires_python_regex_backend
def test_seeded_random_texts_cover_hits_clean_text_long_text_and_non_ascii() -> None:
    rows = [(t, bool(_reference_verdict(t))) for t in _fuzz_texts()]
    texts = [t for t, _ in rows]
    denied = sum(hit for _, hit in rows)
    long_denied = sum(len(t) >= 64 and hit for t, hit in rows)
    long_clean = sum(len(t) >= 64 and not hit for t, hit in rows)
    non_ascii_denied = sum(not t.isascii() and hit for t, hit in rows)
    assert min(denied, len(texts) - denied, long_denied, long_clean, non_ascii_denied) >= 100


# -- shortcut engagement: a gate that never skips is not caught by verdicts alone -------


class _CountingPattern:
    """Compiled-pattern proxy that records the source of every search/findall call."""

    def __init__(self, compiled: re.Pattern[str], log: list[str]) -> None:
        self._compiled = compiled
        self._log = log

    def search(self, *args: Any) -> re.Match[str] | None:
        self._log.append(self._compiled.pattern)
        return self._compiled.search(*args)

    def findall(self, *args: Any) -> list[Any]:
        self._log.append(self._compiled.pattern)
        return self._compiled.findall(*args)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._compiled, name)


class _CountingRe:
    """Stand-in for the ``re`` module alias whose ``compile`` returns counting proxies."""

    def __init__(self, log: list[str]) -> None:
        self._log = log

    def compile(self, pattern: str, flags: int = 0) -> _CountingPattern:
        return _CountingPattern(re.compile(pattern, flags), self._log)

    def __getattr__(self, name: str) -> Any:
        return getattr(re, name)


@contextmanager
def _counting_regexes(log: list[str]) -> Iterator[None]:
    shim = _CountingRe(log)
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(engine_core, "re", shim)
        patch.setattr(rule_module, "re", shim)
        yield


def _counting_engine(rules_factory: Any) -> tuple[GovernanceEngine, list[str]]:
    log: list[str] = []
    with _counting_regexes(log):
        engine = _build_engine(rules_factory())
    log.clear()
    return engine, log


_API_KEY_PATTERN = r"sk-[a-z0-9]{8,}"


def _api_key_rules() -> list[Rule]:
    # No literal anchor word, so the ASCII gate literal ("sk-") alone decides whether it runs.
    return [_rule("API-KEY", patterns=[_API_KEY_PATTERN])]


def _keyword_rules() -> list[Rule]:
    return [_rule("PASSWORD", keywords=["password"]), _rule("EXFIL", keywords=["exfiltrate"])]


@requires_python_regex_backend
class TestShortcutsEngage:
    @pytest.mark.parametrize("length", [20, 64, 65, 200])
    def test_ascii_text_without_the_gate_literal_never_reaches_the_pattern_regex(
        self, length: int
    ) -> None:
        engine, log = _counting_engine(_api_key_rules)
        verdict = _verdict(engine, _clean_text("", length))
        assert (verdict, log.count(_API_KEY_PATTERN)) == ((True, frozenset()), 0)

    def test_ascii_text_with_the_gate_literal_still_reaches_the_pattern_regex(self) -> None:
        engine, log = _counting_engine(_api_key_rules)
        verdict = _verdict(engine, _text("", "sk-abc", 100, "middle"))
        assert (verdict, log.count(_API_KEY_PATTERN)) == ((True, frozenset()), 1)

    def test_text_with_the_gate_literal_and_a_match_is_denied_after_the_regex_runs(self) -> None:
        engine, log = _counting_engine(_api_key_rules)
        verdict = _verdict(engine, _text("", "sk-abcdefgh12", 100, "middle"))
        assert (verdict, log.count(_API_KEY_PATTERN)) == ((False, frozenset({"API-KEY"})), 1)

    def test_non_ascii_text_without_the_gate_literal_still_reaches_the_pattern_regex(self) -> None:
        engine, log = _counting_engine(_api_key_rules)
        verdict = _verdict(engine, _clean_text("", 100, _NON_ASCII_FILLER_WORDS))
        assert (verdict, log.count(_API_KEY_PATTERN)) == ((True, frozenset()), 1)

    @pytest.mark.parametrize("length", [65, 200])
    @pytest.mark.parametrize("prefix", _PREFIXES, ids=["plain", "constructive-verb"])
    def test_long_text_without_any_keyword_never_reaches_the_keyword_regex(
        self, prefix: str, length: int
    ) -> None:
        engine, log = _counting_engine(_keyword_rules)
        verdict = _verdict(engine, _clean_text(prefix, length))
        assert (verdict, log) == ((True, frozenset()), [])

    def test_long_text_with_a_keyword_reaches_the_keyword_regex_and_is_denied(self) -> None:
        engine, log = _counting_engine(_keyword_rules)
        verdict = _verdict(engine, _text("", "exfiltrate", 100, "middle"))
        assert (verdict, bool(log)) == ((False, frozenset({"EXFIL"})), True)


# ---------------------------------------------------------------------------------------
# 4. negative-verb fallback
# ---------------------------------------------------------------------------------------


class _SearchCounter:
    def __init__(self, compiled: re.Pattern[str]) -> None:
        self._compiled = compiled
        self.calls = 0

    def search(self, text: str) -> re.Match[str] | None:
        self.calls += 1
        return self._compiled.search(text)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._compiled, name)


_TABLE_TEXTS = [p.values[0] for p in _NEGATIVE_VERB_TABLE]
_ASCII_TABLE_TEXTS = [t for t in _TABLE_TEXTS if t.isascii()]


def test_literal_shortcut_is_active_for_the_real_negative_verb_regex() -> None:
    literals = engine_core._negative_verb_literals()
    assert literals is not None
    assert literals == engine_core._NEGATIVE_VERB_LITERALS


def test_helper_decides_ascii_text_without_running_the_regex_when_literals_are_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    counter = _SearchCounter(_NEGATIVE_VERBS_RE)
    monkeypatch.setattr(engine_core, "_NEGATIVE_VERBS_RE", counter)
    results = [engine_core._has_negative_verb(t) for t in _ASCII_TABLE_TEXTS]
    assert (results, counter.calls) == ([_regex_says(t) for t in _ASCII_TABLE_TEXTS], 0)


def test_helper_runs_the_regex_for_every_non_ascii_text(monkeypatch: pytest.MonkeyPatch) -> None:
    non_ascii = [t for t in _TABLE_TEXTS if not t.isascii()]
    counter = _SearchCounter(_NEGATIVE_VERBS_RE)
    monkeypatch.setattr(engine_core, "_NEGATIVE_VERBS_RE", counter)
    results = [engine_core._has_negative_verb(t) for t in non_ascii]
    assert (results, counter.calls) == ([_regex_says(t) for t in non_ascii], len(non_ascii))


def test_helper_falls_back_to_the_regex_when_the_literal_switch_is_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    counter = _SearchCounter(_NEGATIVE_VERBS_RE)
    monkeypatch.setattr(engine_core, "_NEGATIVE_VERB_LITERALS", None)
    monkeypatch.setattr(engine_core, "_NEGATIVE_VERBS_RE", counter)
    results = [engine_core._has_negative_verb(t) for t in _TABLE_TEXTS]
    assert (results, counter.calls) == ([_regex_says(t) for t in _TABLE_TEXTS], len(_TABLE_TEXTS))


def _regex_with_extra_word(word: str) -> re.Pattern[str]:
    return re.compile(f"{_NEGATIVE_VERBS_RE.pattern}|{re.escape(word)}", _NEGATIVE_VERBS_RE.flags)


def test_changed_regex_disables_the_literal_switch_and_the_helper_follows_the_regex(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    changed = _regex_with_extra_word("wipe")
    monkeypatch.setattr(engine_core, "_NEGATIVE_VERBS_RE", changed)
    switch = engine_core._negative_verb_literals()
    monkeypatch.setattr(engine_core, "_NEGATIVE_VERB_LITERALS", switch)
    texts = [*_TABLE_TEXTS, "wipe the disk", "please wipe it", "nothing to wipe"]
    assert switch is None
    assert [engine_core._has_negative_verb(t) for t in texts] == [
        bool(changed.search(t)) for t in texts
    ]


def test_stale_literals_would_miss_a_word_only_the_changed_regex_knows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    changed = _regex_with_extra_word("wipe")
    monkeypatch.setattr(engine_core, "_NEGATIVE_VERBS_RE", changed)
    monkeypatch.setattr(
        engine_core, "_NEGATIVE_VERB_LITERALS", engine_core._negative_verb_literals()
    )
    assert engine_core._has_negative_verb("wipe the disk") is True


@pytest.mark.parametrize(
    "variant",
    [
        pytest.param(lambda: _regex_with_extra_word("wipe"), id="extra-word"),
        pytest.param(
            lambda: re.compile(
                "|".join(re.escape(w) for w in reversed(_NEGATIVE_VERBS_LIST)), re.I
            ),
            id="reordered",
        ),
        pytest.param(
            lambda: re.compile("|".join(re.escape(w) for w in _NEGATIVE_VERBS_LIST)),
            id="no-ignorecase",
        ),
        pytest.param(
            lambda: re.compile("|".join(re.escape(w) for w in _NEGATIVE_VERBS_LIST[:-1]), re.I),
            id="missing-word",
        ),
    ],
)
def test_literal_switch_is_off_for_any_regex_that_differs_from_the_rebuild(
    monkeypatch: pytest.MonkeyPatch, variant: Any
) -> None:
    monkeypatch.setattr(engine_core, "_NEGATIVE_VERBS_RE", variant())
    assert engine_core._negative_verb_literals() is None


def test_literal_switch_is_off_when_a_listed_verb_is_not_ascii(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    words = (*_NEGATIVE_VERBS_LIST, f"d{DOTLESS_I}sk")
    monkeypatch.setattr(engine_core, "_NEGATIVE_VERBS_LIST", words)
    monkeypatch.setattr(
        engine_core,
        "_NEGATIVE_VERBS_RE",
        re.compile("|".join(re.escape(w) for w in words), re.IGNORECASE),
    )
    assert engine_core._negative_verb_literals() is None


# ---------------------------------------------------------------------------------------
# 5. _runtime_active_rules
# ---------------------------------------------------------------------------------------

_FAR_FUTURE = "2999-12-31"
_FAR_PAST = "2000-01-01"
_CONTEXTS: list[dict[str, Any] | None] = [
    None,
    {},
    {"env": "prod"},
    {"env": "  PROD "},
    {"environment": "prod"},
    {"env": "dev"},
    {"unrelated": 1},
]


def _plain_rules() -> list[Rule]:
    """Rules with a condition, a deprecated and a disabled rule, and no time bounds."""
    return [
        _rule("ALWAYS", keywords=["wipe disk"]),
        _rule("PROD-ONLY", keywords=["exfiltrate"], condition={"env": "prod"}),
        _rule("RETIRED", keywords=["zzretired"], deprecated=True),
        _rule("SWITCHED-OFF", keywords=["zzoff"], enabled=False),
    ]


def _timed_rules() -> list[Rule]:
    """The same rules, each given an open-ended validity window that always covers today."""
    return [
        r.model_copy(update={"valid_from": _FAR_PAST, "valid_until": _FAR_FUTURE})
        for r in _plain_rules()
    ]


def _runtime_engine(rules: list[Rule]) -> tuple[GovernanceEngine, Constitution]:
    constitution = Constitution.from_rules(rules, name="runtime-rules")
    return GovernanceEngine(constitution, strict=False, freeze_gc=False), constitution


def _active_ids(engine: GovernanceEngine, context: dict[str, Any] | None) -> list[str]:
    return [r.id for r in engine._runtime_active_rules(context)]


def test_plain_rules_route_validate_through_runtime_filtering() -> None:
    engine, _ = _runtime_engine(_plain_rules())
    assert _verdict(engine, "exfiltrate it", context={"env": "prod"}) == (
        False,
        frozenset({"PROD-ONLY"}),
    )


@pytest.mark.parametrize("context", _CONTEXTS, ids=repr)
def test_active_rules_without_time_bounds_equal_the_time_bounded_path(
    context: dict[str, Any] | None,
) -> None:
    plain, _ = _runtime_engine(_plain_rules())
    timed, _ = _runtime_engine(_timed_rules())
    assert _active_ids(plain, context) == _active_ids(timed, context)


def test_active_rules_without_time_bounds_are_not_trivially_empty() -> None:
    plain, _ = _runtime_engine(_plain_rules())
    assert (_active_ids(plain, {"env": "prod"}), _active_ids(plain, {"env": "dev"})) == (
        ["ALWAYS", "PROD-ONLY"],
        ["ALWAYS"],
    )


@pytest.mark.parametrize("context", _CONTEXTS, ids=repr)
@pytest.mark.parametrize(
    "action", ["wipe disk", "exfiltrate it", "zzretired zzoff", "all fine here"]
)
def test_validate_without_time_bounds_equals_validate_on_the_time_bounded_path(
    action: str, context: dict[str, Any] | None
) -> None:
    plain, _ = _runtime_engine(_plain_rules())
    timed, _ = _runtime_engine(_timed_rules())
    assert _verdict(plain, action, context=context) == _verdict(timed, action, context=context)


@pytest.mark.parametrize("stamp", ["2026-01-01", "2026-01-01T12:30:00", "2999-06-01"])
def test_well_formed_caller_timestamp_leaves_rules_without_bounds_active(stamp: str) -> None:
    engine, _ = _runtime_engine(_plain_rules())
    assert _active_ids(engine, {"env": "prod", "timestamp": stamp}) == ["ALWAYS", "PROD-ONLY"]


@pytest.mark.parametrize(
    ("env", "expected"),
    [
        pytest.param({"env": "prod"}, (False, frozenset({"PROD-ONLY"})), id="matching-env"),
        pytest.param({"environment": "PROD"}, (False, frozenset({"PROD-ONLY"})), id="env-alias"),
        pytest.param({"env": "dev"}, (True, frozenset()), id="other-env"),
        pytest.param({}, (True, frozenset()), id="empty-context"),
        pytest.param(None, (True, frozenset()), id="no-context"),
    ],
)
def test_conditional_rule_applies_only_when_the_context_matches(
    env: dict[str, Any] | None, expected: tuple[bool, frozenset[str]]
) -> None:
    engine, _ = _runtime_engine(_plain_rules())
    assert _verdict(engine, "exfiltrate it now", context=env) == expected


def test_unconditional_rule_applies_with_and_without_context() -> None:
    engine, _ = _runtime_engine(_plain_rules())
    verdicts = [_verdict(engine, "wipe disk", context=c) for c in (None, {}, {"env": "dev"})]
    assert verdicts == [(False, frozenset({"ALWAYS"}))] * 3


def test_deprecated_and_disabled_rules_never_apply() -> None:
    engine, _ = _runtime_engine(_plain_rules())
    assert _verdict(engine, "zzretired zzoff", context={"env": "prod"}) == (True, frozenset())


def test_rule_expired_after_construction_stops_applying() -> None:
    engine, constitution = _runtime_engine(_plain_rules())
    before = _verdict(engine, "wipe disk")
    constitution.rules[0].valid_until = _FAR_PAST
    after = _verdict(engine, "wipe disk")
    assert (before, after) == ((False, frozenset({"ALWAYS"})), (True, frozenset()))


def test_rule_expired_after_construction_is_dropped_from_the_active_rules() -> None:
    engine, constitution = _runtime_engine(_plain_rules())
    constitution.rules[0].valid_until = _FAR_PAST
    assert _active_ids(engine, {"env": "prod"}) == ["PROD-ONLY"]


def test_rule_that_starts_in_the_future_after_construction_does_not_apply_yet() -> None:
    engine, constitution = _runtime_engine(_plain_rules())
    constitution.rules[0].valid_from = _FAR_FUTURE
    assert _verdict(engine, "wipe disk") == (True, frozenset())


def test_rule_with_a_window_covering_today_keeps_applying_after_construction() -> None:
    engine, constitution = _runtime_engine(_plain_rules())
    constitution.rules[0].valid_from = _FAR_PAST
    constitution.rules[0].valid_until = _FAR_FUTURE
    assert _verdict(engine, "wipe disk") == (False, frozenset({"ALWAYS"}))


def test_rule_expired_in_a_time_bounded_constitution_stops_applying() -> None:
    engine, constitution = _runtime_engine(_timed_rules())
    before = _verdict(engine, "wipe disk")
    constitution.rules[0].valid_until = _FAR_PAST
    assert (before, _verdict(engine, "wipe disk")) == (
        (False, frozenset({"ALWAYS"})),
        (True, frozenset()),
    )


@pytest.mark.parametrize(
    ("stamp", "applies"),
    [
        pytest.param("1999-06-01", True, id="before-the-window-closes"),
        pytest.param(_FAR_PAST, True, id="window-end-is-inclusive"),
        pytest.param("2000-01-02", False, id="after-the-window"),
    ],
)
def test_caller_timestamp_decides_validity_instead_of_the_clock(stamp: str, applies: bool) -> None:
    rule = _rule("OLD-WINDOW", keywords=["wipe disk"], valid_until=_FAR_PAST)
    engine, _ = _runtime_engine([rule])
    expected = (False, frozenset({"OLD-WINDOW"})) if applies else (True, frozenset())
    assert _verdict(engine, "wipe disk", context={"timestamp": stamp}) == expected


def test_window_in_the_past_does_not_apply_without_a_caller_timestamp() -> None:
    rule = _rule("OLD-WINDOW", keywords=["wipe disk"], valid_until=_FAR_PAST)
    engine, _ = _runtime_engine([rule])
    assert _verdict(engine, "wipe disk") == (True, frozenset())


@pytest.mark.parametrize("key", ["timestamp", "evaluation_time", "valid_at", "at"])
def test_malformed_caller_timestamp_raises_value_error_in_every_accepted_key(key: str) -> None:
    engine, _ = _runtime_engine(_plain_rules())
    with pytest.raises(ValueError):
        engine.validate("wipe disk", context={key: "not-a-date"})


@pytest.mark.parametrize("key", ["timestamp", "evaluation_time", "valid_at", "at"])
def test_malformed_caller_timestamp_raises_value_error_from_the_rule_filter(key: str) -> None:
    engine, _ = _runtime_engine(_plain_rules())
    with pytest.raises(ValueError):
        engine._runtime_active_rules({key: "2026-13-45"})


@pytest.mark.parametrize("bad", ["yesterday", "2026/01/01", "12:30", "2026-01-01T99:00:00"])
def test_malformed_timestamp_in_a_time_bounded_constitution_raises_value_error(bad: str) -> None:
    engine, _ = _runtime_engine(_timed_rules())
    with pytest.raises(ValueError):
        engine.validate("wipe disk", context={"timestamp": bad})


@pytest.mark.parametrize("ignored", ["", 12345, None, ["2026-01-01"]], ids=repr)
def test_empty_or_non_string_timestamp_is_ignored_and_the_clock_is_used(ignored: Any) -> None:
    engine, _ = _runtime_engine(_plain_rules())
    assert _verdict(engine, "wipe disk", context={"timestamp": ignored}) == (
        False,
        frozenset({"ALWAYS"}),
    )


def test_first_accepted_timestamp_key_wins_over_a_malformed_later_one() -> None:
    engine, _ = _runtime_engine(_plain_rules())
    context = {"timestamp": "2026-01-01", "at": "not-a-date"}
    assert _verdict(engine, "wipe disk", context=context) == (False, frozenset({"ALWAYS"}))
