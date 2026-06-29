"""Analysis pipeline orchestrator."""

from __future__ import annotations

import hashlib
import logging
import re
import time
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.cache import cache_get, cache_set
from app.core.config import get_settings
from app.models.report import ScanReport
from app.models.schemas import (
    AnalysisReport,
    BehaviorReport,
    IOCReport,
    ScanStatus,
    TimelineEvent,
)
from app.services.ml.scorer import compute_risk_score, score_sample
from app.services.sandbox.executor import run_sandbox
from app.services.static.analyzer import analyze_static
from app.services.yara.engine import scan_with_yara

logger = logging.getLogger(__name__)
_stats = {"cache_hits": 0}


def get_cache_stats() -> dict[str, int]:
    return dict(_stats)


def _file_hashes(data: bytes) -> tuple[str, str]:
    return hashlib.sha256(data).hexdigest(), hashlib.md5(data).hexdigest()


def _extract_iocs(
    static_dict: dict,
    sandbox_dict: dict,
    sha256: str,
    md5: str,
) -> dict[str, Any]:
    domains: set[str] = set()
    ips: set[str] = set()
    urls: set[str] = set()
    file_paths: set[str] = set()
    registry_keys: set[str] = set()

    url_pattern = re.compile(r"https?://[^\s\"']+", re.IGNORECASE)
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    domain_pattern = re.compile(r"\b[a-z0-9][a-z0-9.-]+\.[a-z]{2,}\b", re.IGNORECASE)

    for s in static_dict.get("strings", []):
        urls.update(url_pattern.findall(s))
        ips.update(ip_pattern.findall(s))
        domains.update(domain_pattern.findall(s))

    for call in sandbox_dict.get("network_calls", []):
        dest = call.get("destination", "")
        if dest:
            domains.add(dest)

    for op in sandbox_dict.get("file_operations", []):
        path = op.get("path")
        if path:
            file_paths.add(path)

    for op in sandbox_dict.get("registry_operations", []):
        key = op.get("key")
        if key:
            registry_keys.add(key)

    return IOCReport(
        hashes={"sha256": sha256, "md5": md5},
        domains=sorted(domains),
        ips=sorted(ips),
        urls=sorted(urls),
        file_paths=sorted(file_paths),
        registry_keys=sorted(registry_keys),
    ).model_dump()


def _build_behavior(sandbox_dict: dict) -> dict[str, Any]:
    processes = [p.get("name", "") for p in sandbox_dict.get("process_tree", [])]
    domains = [c.get("destination", "") for c in sandbox_dict.get("network_calls", [])]
    file_writes = [
        op.get("path", "") for op in sandbox_dict.get("file_operations", [])
        if op.get("action") == "write"
    ]
    registry = [op.get("key", "") for op in sandbox_dict.get("registry_operations", [])]

    return BehaviorReport(
        processes=processes,
        domains=domains,
        file_writes=file_writes,
        registry_changes=registry,
        network_connections=sandbox_dict.get("network_calls", []),
    ).model_dump()


async def run_analysis_pipeline(
    db: AsyncSession,
    data: bytes,
    filename: str,
    use_cache: bool = True,
) -> ScanReport:
    settings = get_settings()
    sha256, md5 = _file_hashes(data)
    timeline: list[dict] = []
    t0 = time.time()

    if use_cache and settings.enable_cache:
        cached = cache_get(f"report:{sha256}")
        if cached:
            _stats["cache_hits"] += 1
            logger.info("Cache hit sha256=%s filename=%s", sha256[:16], filename)
            report = ScanReport(
                sha256=sha256,
                md5=md5,
                filename=filename,
                file_size=len(data),
                status=ScanStatus.cached.value,
                **{k: cached[k] for k in (
                    "risk_score", "flags", "static_analysis", "sandbox_analysis",
                    "ml_analysis", "yara_matches", "behavior", "iocs", "timeline",
                ) if k in cached},
            )
            db.add(report)
            await db.commit()
            await db.refresh(report)
            return report

    report = ScanReport(
        sha256=sha256,
        md5=md5,
        filename=filename,
        file_size=len(data),
        status=ScanStatus.pending.value,
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)
    logger.info("Scan started id=%s sha256=%s filename=%s size=%d", report.id, sha256[:16], filename, len(data))

    try:
        # Static analysis
        report.status = ScanStatus.static.value
        await db.commit()
        timeline.append(TimelineEvent(
            timestamp=time.time() - t0, phase="static", event="analysis_started",
        ).model_dump())

        static = analyze_static(data, filename)
        static_dict = static.model_dump()
        timeline.append(TimelineEvent(
            timestamp=time.time() - t0, phase="static", event="analysis_complete",
            details={"indicators": static.suspicious_indicators},
        ).model_dump())
        report.static_analysis = static_dict

        # YARA
        yara_matches = scan_with_yara(data)
        report.yara_matches = [m.model_dump() for m in yara_matches]
        if yara_matches:
            timeline.append(TimelineEvent(
                timestamp=time.time() - t0, phase="yara", event="rules_matched",
                details={"count": len(yara_matches)},
            ).model_dump())

        # Sandbox
        sandbox_dict: dict = {}
        if settings.enable_sandbox:
            report.status = ScanStatus.sandbox.value
            await db.commit()
            timeline.append(TimelineEvent(
                timestamp=time.time() - t0, phase="sandbox", event="vm_started",
            ).model_dump())

            sandbox = run_sandbox(data, static, timeout=settings.sandbox_timeout_seconds)
            sandbox_dict = sandbox.model_dump()
            report.sandbox_analysis = sandbox_dict
            timeline.append(TimelineEvent(
                timestamp=time.time() - t0, phase="sandbox", event="execution_complete",
                details={"verdict": sandbox.verdict, "duration": sandbox.duration_seconds},
            ).model_dump())

        # ML scoring
        report.status = ScanStatus.ml.value
        await db.commit()
        sandbox_obj = None
        if sandbox_dict:
            from app.models.schemas import SandboxResult
            sandbox_obj = SandboxResult(**sandbox_dict)

        ml = score_sample(static, sandbox_obj)
        report.ml_analysis = ml.model_dump()
        timeline.append(TimelineEvent(
            timestamp=time.time() - t0, phase="ml", event="scoring_complete",
            details={"model": ml.model, "probability": ml.probability_malicious},
        ).model_dump())

        risk_score, flags = compute_risk_score(static, sandbox_obj, ml, len(yara_matches))
        report.risk_score = risk_score
        report.flags = flags
        report.behavior = _build_behavior(sandbox_dict)
        report.iocs = _extract_iocs(static_dict, sandbox_dict, sha256, md5)
        report.timeline = timeline
        report.status = ScanStatus.completed.value
        report.completed_at = datetime.utcnow()

        cache_payload = {
            "risk_score": risk_score,
            "flags": flags,
            "static_analysis": static_dict,
            "sandbox_analysis": sandbox_dict,
            "ml_analysis": ml.model_dump(),
            "yara_matches": report.yara_matches,
            "behavior": report.behavior,
            "iocs": report.iocs,
            "timeline": timeline,
        }
        if settings.enable_cache:
            cache_set(f"report:{sha256}", cache_payload)

        logger.info(
            "Scan complete id=%s risk=%.1f flags=%s duration=%.2fs",
            report.id, risk_score, flags, time.time() - t0,
        )

    except Exception as exc:
        logger.exception("Scan failed id=%s sha256=%s: %s", report.id, sha256[:16], exc)
        report.status = ScanStatus.failed.value
        report.error_message = str(exc)
        report.completed_at = datetime.utcnow()

    await db.commit()
    await db.refresh(report)
    return report


async def get_report_by_id(db: AsyncSession, scan_id: str) -> ScanReport | None:
    result = await db.execute(select(ScanReport).where(ScanReport.id == scan_id))
    return result.scalar_one_or_none()


async def get_report_by_hash(db: AsyncSession, sha256: str) -> ScanReport | None:
    result = await db.execute(
        select(ScanReport)
        .where(ScanReport.sha256 == sha256)
        .order_by(ScanReport.created_at.desc())
    )
    return result.scalars().first()
# Project version: ThreatVault V1.1
