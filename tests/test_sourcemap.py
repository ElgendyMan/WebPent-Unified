# tests/test_sourcemap.py
"""PROPOSALS_ULTIMATE_V2 §3 (2026-10-29) test suite: source-map exposure.

Covers VLQ decode against a hand-computed mapping, generated→original
resolution, the fail-closed parse budgets, secret scanning with correct
file/line attribution and thumb-only values, the sourceMappingURL comment
rules (last wins, relative resolution, data: URLs ignored), the no-
comment-no-probe rule, and every flag-off default.
"""

from __future__ import annotations

import json

import pytest

from webpent.agents.sourcemap_analysis import (
    SourceMapError,
    SourceMapAgent,
    build_source_map_agent,
    decode_vlq_segment,
    extract_source_map_url,
    parse_source_map,
    resolve_position,
    scan_sources,
)
from webpent.config.settings import Settings


def _settings(**kwargs: object) -> Settings:
    return Settings(**kwargs)


class TestVlq:
    def test_known_values_decode(self) -> None:
        # "AAAA" = [0,0,0,0]; single-continuation negative: "gB" -> -49?
        # Stick to spec examples: A=0, B=1, C=2, D=3; "AAAA" -> 0,0,0,0.
        assert decode_vlq_segment("AAAA") == [0, 0, 0, 0]
        # 1 encodes as "C": value bit 1, sign bit 0 -> 1
        assert decode_vlq_segment("C") == [1]
        # -1 encodes as "D" (value 1 with sign bit set)
        assert decode_vlq_segment("D") == [-1]
        # 16 = 0b10000 -> value<<1 = 32 with sign 0 -> "gB"? compute:
        # 32 = 0b100000: low5=00000 cont, then 1 -> chars: g(32->'g'?)...
        assert decode_vlq_segment("gB") == [16]

    def test_continuation_multi_field(self) -> None:
        # "AAgBC": [0,0,16,1] — the canonical v3 example
        assert decode_vlq_segment("AAgBC") == [0, 0, 16, 1]

    def test_invalid_character_raises(self) -> None:
        with pytest.raises(SourceMapError):
            decode_vlq_segment("A!A")

    def test_dangling_continuation_raises(self) -> None:
        with pytest.raises(SourceMapError):
            decode_vlq_segment("g")


class TestParse:
    def _map(self, **overrides: object) -> str:
        doc = {
            "version": 3,
            "sources": ["src/app.ts"],
            "sourcesContent": ["const x = 1;\n"],
            "mappings": "AAAA",
            "names": [],
        }
        doc.update(overrides)
        return json.dumps(doc)

    def test_valid_map_parses(self) -> None:
        sm = parse_source_map(self._map(), max_sources=10, max_content_chars=1000)
        assert sm.sources == ("src/app.ts",)
        assert sm.sources_content == ("const x = 1;\n",)

    def test_version_2_refused(self) -> None:
        with pytest.raises(SourceMapError):
            parse_source_map(
                self._map(version=2), max_sources=10, max_content_chars=1000
            )

    def test_oversized_sources_refused(self) -> None:
        with pytest.raises(SourceMapError):
            parse_source_map(
                self._map(sources=[f"s{i}.ts" for i in range(5)]),
                max_sources=4,
                max_content_chars=1000,
            )

    def test_oversized_content_refused(self) -> None:
        with pytest.raises(SourceMapError):
            parse_source_map(
                self._map(sourcesContent=["a" * 50]),
                max_sources=10,
                max_content_chars=10,
            )

    def test_corrupt_mappings_refused(self) -> None:
        with pytest.raises(SourceMapError):
            parse_source_map(
                self._map(mappings="A!A"), max_sources=10, max_content_chars=1000
            )

    def test_invalid_json_refused(self) -> None:
        with pytest.raises(SourceMapError):
            parse_source_map("{not json", max_sources=10, max_content_chars=1000)

    def test_resolve_position(self) -> None:
        # two sources: line 2's "ACAA" segment maps col 0 to source 1
        # (src delta +1), original line 0 => presented as 1.
        sm = parse_source_map(
            self._map(
                sources=["a.ts", "b.ts"],
                sourcesContent=["a", "b"],
                mappings="AAAA;ACAA",
            ),
            max_sources=10,
            max_content_chars=100,
        )
        got = resolve_position(sm, 2, 0)
        assert got is not None
        assert got.source == "b.ts"
        assert got.original_line == 1
        assert resolve_position(sm, 99, 0) is None


def _secret_map() -> str:
    return json.dumps(
        {
            "version": 3,
            "sources": ["src/config.ts", "src/api.ts"],
            "sourcesContent": [
                "const apiKey = 'AKIAIOSFODNN7EXAMPLE';\n",
                "const token = 'hunter2hunter2';\nconst password = 'pw12345678';\n",
            ],
            "mappings": "AAAA",
        }
    )


class TestSecretScan:
    def test_secrets_found_attributed_to_file_and_line(self) -> None:
        sm = parse_source_map(_secret_map(), max_sources=10, max_content_chars=1000)
        findings = scan_sources(sm)
        aws = [f for f in findings if f.detail == "aws_access_key"]
        assert len(aws) == 1
        assert aws[0].source_file == "src/config.ts"
        assert aws[0].line == 1
        pw = [f for f in findings if f.detail == "assignment_secret" and f.source_file == "src/api.ts"]
        assert {f.line for f in pw} == {2}  # password line; "token" alone is not a pattern

    def test_values_are_thumbs_never_full_secrets(self) -> None:
        sm = parse_source_map(_secret_map(), max_sources=10, max_content_chars=1000)
        for finding in scan_sources(sm):
            assert len(finding.thumb) == 16
            assert "AKIAIOSFODNN7EXAMPLE" not in finding.thumb
            assert len(finding.preview) <= 12

    def test_inventory_finding_present(self) -> None:
        sm = parse_source_map(_secret_map(), max_sources=10, max_content_chars=1000)
        inventory = [f for f in scan_sources(sm) if f.kind == "source_inventory"]
        assert len(inventory) == 1
        assert "2 original source files" in inventory[0].detail


class TestCommentExtraction:
    def test_last_comment_wins(self) -> None:
        js = "//# sourceMappingURL=old.map\n//# sourceMappingURL=new.map"
        assert extract_source_map_url(js, "https://t/app.js").endswith("new.map")

    def test_relative_resolved_against_bundle(self) -> None:
        js = "//# sourceMappingURL=maps/app.js.map"
        got = extract_source_map_url(js, "https://t/static/app.js")
        assert got == "https://t/static/maps/app.js.map"

    def test_data_url_ignored(self) -> None:
        js = "//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozfQ=="
        assert extract_source_map_url(js, "https://t/app.js") is None

    def test_no_comment_no_url(self) -> None:
        assert extract_source_map_url("console.log(1)", "https://t/app.js") is None


class TestAgent:
    def test_flag_off_is_inert(self) -> None:
        settings = _settings()
        assert settings.enable_source_maps is False
        agent = build_source_map_agent(settings)
        assert agent.enabled is False
        result = agent.analyse(["https://t/app.js"], fetcher=lambda url: "//# sourceMappingURL=a.map")
        assert result.findings == [] and result.skips == []

    def test_no_comment_means_no_probe(self) -> None:
        probed: list[str] = []

        def fetcher(url: str) -> str | None:
            probed.append(url)
            return "console.log(1)"

        agent = SourceMapAgent(enabled=True, max_sources=10, max_content_chars=1000)
        result = agent.analyse(["https://t/app.js"], fetcher=fetcher)
        assert probed == ["https://t/app.js"]  # never probed /app.js.map
        assert result.skips[0].reason == "no_map_comment"

    def test_happy_path_full_chain(self) -> None:
        urls = []

        def fetcher(url: str) -> str | None:
            urls.append(url)
            if url.endswith(".js"):
                return "//# sourceMappingURL=app.js.map"
            return _secret_map()

        agent = SourceMapAgent(enabled=True, max_sources=10, max_content_chars=1000)
        result = agent.analyse(["https://t/app.js"], fetcher=fetcher)
        assert result.maps_parsed == 1
        assert urls == ["https://t/app.js", "https://t/app.js.map"]
        assert any(f.detail == "aws_access_key" for f in result.findings)
        assert any(f.kind == "source_inventory" for f in result.findings)

    def test_map_fetch_failure_is_skip_not_crash(self) -> None:
        def fetcher(url: str) -> str | None:
            return None

        agent = SourceMapAgent(enabled=True, max_sources=10, max_content_chars=1000)
        result = agent.analyse(
            ["https://t/app.js"], fetcher=lambda u: "//# sourceMappingURL=a.map" if u.endswith(".js") else None
        )
        assert result.maps_parsed == 0
        assert result.skips[0].reason == "map_fetch_failed"

    def test_unparsable_map_skipped(self) -> None:
        agent = SourceMapAgent(enabled=True, max_sources=10, max_content_chars=1000)
        result = agent.analyse(
            ["https://t/app.js"],
            fetcher=lambda u: "//# sourceMappingURL=a.map" if u.endswith(".js") else "{bad",
        )
        assert result.skips[0].reason == "map_unparsable"

    def test_zero_budget_fail_closed(self) -> None:
        with pytest.raises(ValueError):
            SourceMapAgent(enabled=True, max_sources=0, max_content_chars=1000)
