"""YARA rules engine."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from app.core.config import get_settings
from app.models.schemas import YaraMatch

logger = logging.getLogger(__name__)
_yara_rules = None
_fallback_logged = False


def _compile_rules() -> Any | None:
    global _yara_rules
    if _yara_rules is not None:
        return _yara_rules

    settings = get_settings()
    if not settings.enable_yara:
        return None

    rules_dir = settings.yara_rules_dir.resolve()
    if not rules_dir.exists():
        return None

    try:
        import yara

        rule_files = list(rules_dir.glob("*.yar")) + list(rules_dir.glob("*.yara"))
        if not rule_files:
            return None

        filepaths = {f"rule_{i}": str(f) for i, f in enumerate(rule_files)}
        _yara_rules = yara.compile(filepaths=filepaths)
        return _yara_rules
    except Exception:
        return None


def scan_with_yara(data: bytes) -> list[YaraMatch]:
    global _fallback_logged
    rules = _compile_rules()
    if not rules:
        if not _fallback_logged:
            logger.info("YARA native module unavailable — using pattern-based fallback")
            _fallback_logged = True
        return _fallback_yara_scan(data)

    matches: list[YaraMatch] = []
    for match in rules.match(data=data):
        matched_strings = [s.identifier for s in match.strings[:10]]
        matches.append(YaraMatch(
            rule=match.rule,
            namespace=match.namespace,
            tags=list(match.tags),
            meta=dict(match.meta) if match.meta else {},
            strings=matched_strings,
        ))
    return matches


def _fallback_yara_scan(data: bytes) -> list[YaraMatch]:
    """Pattern-based fallback when yara-python is unavailable."""
    matches: list[YaraMatch] = []
    patterns = {
        "Suspicious_PowerShell": [b"powershell", b"-enc ", b"IEX("],
        "Suspicious_Network": [b"http://", b"https://", b"URLDownloadToFile"],
        "Suspicious_Injection": [b"VirtualAlloc", b"WriteProcessMemory", b"CreateRemoteThread"],
        "Ransomware_Indicators": [b".encrypted", b"bitcoin", b"ransom"],
    }

    lower_data = data.lower()
    for rule_name, sigs in patterns.items():
        hit_strings = [sig.decode("utf-8", errors="ignore") for sig in sigs if sig.lower() in lower_data]
        if hit_strings:
            matches.append(YaraMatch(
                rule=rule_name,
                namespace="fallback",
                tags=["auto", "fallback"],
                meta={"author": "ThreatVault", "severity": "medium"},
                strings=hit_strings,
            ))
    return matches
# Project version: ThreatVault V1.1
