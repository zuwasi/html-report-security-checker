"""Regular-expression definitions for HTML security checks."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Pattern


FLAGS = re.IGNORECASE | re.MULTILINE
DOTALL_FLAGS = FLAGS | re.DOTALL


@dataclass(frozen=True)
class CheckDefinition:
    """Metadata and detection patterns for one security check."""

    id: str
    name: str
    severity: str
    description: str
    patterns: list[tuple[Pattern[str], str]]


def _compile(pattern: str, *, dotall: bool = False) -> Pattern[str]:
    """Compile a rule with the common case-insensitive, multiline flags."""
    return re.compile(pattern, DOTALL_FLAGS if dotall else FLAGS)


COMMENT_PREFIX = r"<!--(?:(?!-->)[\s\S])*?"
COMMENT_SUFFIX = r"(?:(?!-->)[\s\S])*?-->"

CHECK_DEFINITIONS = [
    CheckDefinition(
        "SEC-01",
        "Secrets in HTML comments",
        "error",
        "HTML comments must not contain credentials or private keys.",
        [
            (
                _compile(
                    COMMENT_PREFIX
                    + r"(?:sk-[A-Za-z0-9_-]{8,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{8,}|github_pat_[A-Za-z0-9_]{8,}|xoxb-[A-Za-z0-9-]{8,}|AIza[A-Za-z0-9_-]{8,})"
                    + COMMENT_SUFFIX
                ),
                "Possible API key found in an HTML comment.",
            ),
            (
                _compile(COMMENT_PREFIX + r"-----BEGIN(?: [A-Z]+)? PRIVATE KEY-----" + COMMENT_SUFFIX),
                "Private key material found in an HTML comment.",
            ),
            (
                _compile(
                    COMMENT_PREFIX
                    + r"\b(?:password|passwd|secret)\b\s*[:=]\s*['\"]?[^\s'\"<>]{4,}"
                    + COMMENT_SUFFIX
                ),
                "Possible password or secret found in an HTML comment.",
            ),
        ],
    ),
    CheckDefinition(
        "SEC-02",
        "Hardcoded passwords in JavaScript",
        "error",
        "JavaScript must not contain literal password values.",
        [
            (
                _compile(r"\b(?:password|passwd)\b\s*={2,3}\s*(['\"])(?=.)[^'\"\r\n]+\1"),
                "Password is compared with a hardcoded string literal.",
            ),
            (
                _compile(r"\b(?:const|let|var)\s+(?:password|passwd)\s*=\s*(['\"])(?=.)[^'\"\r\n]+\1"),
                "A password variable is assigned a hardcoded string literal.",
            ),
        ],
    ),
    CheckDefinition(
        "SEC-03",
        "Tracking and outbound network calls",
        "warning",
        "Outbound calls and analytics may disclose report-viewing activity.",
        [
            (_compile(r"\bfetch\s*\(\s*['\"]https?://[^'\"]+['\"]"), "External fetch() call found."),
            (_compile(r"\bfetch\s*\(\s*['\"][^'\"]*(?:track|analytics)[^'\"]*['\"]"), "fetch() targets a tracking or analytics URL."),
            (_compile(r"\b(?:new\s+)?XMLHttpRequest\b[\s\S]{0,500}?\.open\s*\([^)]*['\"]https?://", dotall=True), "XMLHttpRequest opens an external URL."),
            (_compile(r"<script\b[^>]*\bsrc\s*=\s*['\"][^'\"]*(?:google-analytics|abacus|mixpanel|segment|amplitude)[^'\"]*['\"][^>]*>"), "Analytics script found."),
            (_compile(r"\bnavigator\.sendBeacon\s*\("), "navigator.sendBeacon() may transmit tracking data."),
        ],
    ),
    CheckDefinition(
        "SEC-04",
        "External scripts without SRI",
        "warning",
        "External scripts should use Subresource Integrity (SRI).",
        [
            (
                _compile(r"<script\b(?![^>]*\bintegrity\s*=)[^>]*\bsrc\s*=\s*['\"]https?://[^'\"]+['\"][^>]*>"),
                "External script tag has no integrity attribute.",
            )
        ],
    ),
    CheckDefinition(
        "SEC-05",
        "Missing Content-Security-Policy",
        "info",
        "A Content-Security-Policy meta tag reduces the impact of injected content.",
        [
            (
                _compile(r"\A(?![\s\S]*<meta\b[^>]*\bhttp-equiv\s*=\s*['\"]Content-Security-Policy['\"])[\s\S]*\Z"),
                "No Content-Security-Policy meta tag was found.",
            )
        ],
    ),
    CheckDefinition(
        "SEC-06",
        "YouTube embeds without privacy mode",
        "warning",
        "YouTube embeds should use the youtube-nocookie.com privacy domain.",
        [
            (
                _compile(r"<iframe\b[^>]*\bsrc\s*=\s*['\"]https?://(?![^'\"]*youtube-nocookie\.com)[^'\"]*youtube\.com/(?:embed|v)/[^'\"]*['\"][^>]*>"),
                "YouTube iframe does not use privacy-enhanced mode.",
            )
        ],
    ),
    CheckDefinition(
        "SEC-07",
        "AI prompt leakage",
        "error",
        "Generated reports must not expose AI prompts or instructions.",
        [
            (
                _compile(r"(?:<!--(?=(?:(?!-->)[\s\S])*(?:You are (?:a|an)\b|system prompt|ignore previous instructions|act as\b|pretend you are|IMPORTANT:\s*You must|<system>|\[INST\]|Your task is to))(?:(?!-->)[\s\S])*?-->|<script\b[^>]*>(?=(?:(?!</script>)[\s\S])*(?:You are (?:a|an)\b|system prompt|ignore previous instructions|act as\b|pretend you are|IMPORTANT:\s*You must|<system>|\[INST\]|Your task is to))(?:(?!</script>)[\s\S])*?</script>)"),
                "Text resembling an AI system prompt or instruction was exposed.",
            )
        ],
    ),
    CheckDefinition(
        "SEC-08",
        "Unsafe target=\"_blank\"",
        "info",
        "New-window links should prevent opener access and referrer leakage.",
        [
            (
                _compile(r"<a\b(?=[^>]*\btarget\s*=\s*['\"]_blank['\"])(?![^>]*\brel\s*=\s*['\"][^'\"]*\b(?:noopener|noreferrer)\b)[^>]*>"),
                "Link opens a new window without rel=noopener or noreferrer.",
            )
        ],
    ),
    CheckDefinition(
        "SEC-09",
        "Unversioned CDN scripts",
        "warning",
        "CDN dependencies should be pinned to an explicit version.",
        [
            (
                _compile(r"<script\b[^>]*\bsrc\s*=\s*['\"]https?://(?:cdn[^/'\"]*|unpkg\.com|cdnjs\.cloudflare\.com)/(?![^'\"]*(?:@|/|\bv)\d+\.\d+\.\d+(?:[./?_-]|$))[^'\"]+['\"][^>]*>"),
                "CDN script URL does not contain a semantic version.",
            )
        ],
    ),
]

