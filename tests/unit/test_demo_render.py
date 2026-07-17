from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from domestique.cli import _render_canned, _render_config_header
from domestique.config import Settings
from domestique.gateway import build_wedge_pipeline
from domestique.policy import PolicyEngine

if TYPE_CHECKING:
    from domestique.detectors.registry import InspectionResult


class TestConfigHeader:
    def test_shows_active_preset_and_regex_on(self) -> None:
        settings = Settings()  # regex on, preset default "balanced"
        out = _render_config_header(settings, PolicyEngine.from_yaml_default(), color=False)
        assert "Regex" in out
        assert "[balanced]" in out  # active preset bracketed
        assert "redact on" in out
        assert "block on" in out  # wedge policy blocks crown-jewels
        assert "\033[" not in out  # color=False -> no ANSI

    def test_disabled_tiers_marked(self) -> None:
        out = _render_config_header(Settings(), PolicyEngine.from_yaml_default(), color=False)
        assert "GLiNER" in out


class TestCanned:
    def _run(self, text: str) -> InspectionResult:
        return asyncio.run(build_wedge_pipeline().inspect(text))

    def test_shows_before_after_and_findings(self) -> None:
        text = "my aws key AKIAIOSFODNN7EXAMPLE and email a@b.com"
        res = self._run(text)
        out = _render_canned(text, res.redacted_text or text, res.findings, color=False)
        assert "BEFORE" in out
        assert "AFTER" in out
        assert "[AWS_ACCESS_KEY_REDACTED]" in out  # token present in AFTER
        assert "AWS access key" in out  # finding label
        assert "\033[" not in out  # no color when color=False

    def test_color_highlights_when_enabled(self) -> None:
        text = "key AKIAIOSFODNN7EXAMPLE"
        res = self._run(text)
        out = _render_canned(text, res.redacted_text or text, res.findings, color=True)
        assert "\033[31m" in out  # red used for a leaked secret
        assert "\033[32m" in out  # green used for a token
