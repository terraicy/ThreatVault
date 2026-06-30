import logging

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import get_db
from app.models.report import ScanReport
from app.models.schemas import AnalysisReport, PlatformStats, ScanResponse, ScanStatus
from app.services.pipeline import get_cache_stats, get_report_by_hash, get_report_by_id, run_analysis_pipeline

router = APIRouter()
logger = logging.getLogger(__name__)


def _to_analysis_report(report: ScanReport) -> AnalysisReport:
    return AnalysisReport.model_validate(report)


@router.post("/scan", response_model=ScanResponse)
@router.post("/submit-sample", response_model=ScanResponse)
async def scan_file(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
):
    settings = get_settings()
    data = await file.read()
    max_bytes = settings.max_upload_mb * 1024 * 1024

    if len(data) == 0:
        raise HTTPException(status_code=400, detail="Empty file")
    if len(data) > max_bytes:
        raise HTTPException(status_code=413, detail=f"File exceeds {settings.max_upload_mb}MB limit")

    filename = file.filename or "unknown"
    logger.info("Upload received filename=%s size=%d", filename, len(data))
    report = await run_analysis_pipeline(db, data, filename)

    return ScanResponse(
        scan_id=report.id,
        sha256=report.sha256,
        status=ScanStatus(report.status),
        message="Analysis complete" if report.status == ScanStatus.completed.value else report.status,
        cached=report.status == ScanStatus.cached.value,
    )


@router.get("/report/{scan_id}", response_model=AnalysisReport)
async def get_report(scan_id: str, db: AsyncSession = Depends(get_db)):
    report = await get_report_by_id(db, scan_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return _to_analysis_report(report)


@router.get("/report/hash/{sha256}", response_model=AnalysisReport)
async def get_report_by_sha256(sha256: str, db: AsyncSession = Depends(get_db)):
    report = await get_report_by_hash(db, sha256.lower())
    if not report:
        raise HTTPException(status_code=404, detail="Report not found for hash")
    return _to_analysis_report(report)


@router.get("/ioc/{scan_id}")
async def get_iocs(scan_id: str, db: AsyncSession = Depends(get_db)):
    report = await get_report_by_id(db, scan_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report.iocs or {}


@router.get("/stats", response_model=PlatformStats)
async def platform_stats(db: AsyncSession = Depends(get_db)):
    total = await db.scalar(select(func.count()).select_from(ScanReport)) or 0
    completed = await db.scalar(
        select(func.count()).select_from(ScanReport).where(ScanReport.status == "completed")
    ) or 0
    high_risk = await db.scalar(
        select(func.count()).select_from(ScanReport).where(ScanReport.risk_score >= 70)
    ) or 0
    avg_score = await db.scalar(select(func.avg(ScanReport.risk_score))) or 0.0

    rows = await db.execute(
        select(ScanReport.flags).where(ScanReport.flags.isnot(None))
    )
    flag_counts: dict[str, int] = {}
    for (flags,) in rows:
        if flags:
            for f in flags:
                flag_counts[f] = flag_counts.get(f, 0) + 1

    top_flags = sorted(
        [{"flag": k, "count": v} for k, v in flag_counts.items()],
        key=lambda x: x["count"],
        reverse=True,
    )[:10]

    return PlatformStats(
        total_scans=total,
        completed_scans=completed,
        high_risk_samples=high_risk,
        cache_hits=get_cache_stats().get("cache_hits", 0),
        avg_risk_score=round(float(avg_score), 2),
        top_flags=top_flags,
    )


@router.get("/reports", response_model=list[AnalysisReport])
async def list_reports(limit: int = 50, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(ScanReport).order_by(ScanReport.created_at.desc()).limit(min(limit, 200))
    )
    return [_to_analysis_report(r) for r in result.scalars().all()]
# Project version: ThreatVault V1.2
