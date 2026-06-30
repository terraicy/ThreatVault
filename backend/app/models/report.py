from datetime import datetime
from uuid import uuid4

from sqlalchemy import JSON, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class ScanReport(Base):
    __tablename__ = "scan_reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    md5: Mapped[str] = mapped_column(String(32), index=True)
    filename: Mapped[str] = mapped_column(String(512))
    file_size: Mapped[int] = mapped_column(Integer)
    mime_type: Mapped[str] = mapped_column(String(128), default="application/octet-stream")
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)

    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    flags: Mapped[list] = mapped_column(JSON, default=list)
    static_analysis: Mapped[dict] = mapped_column(JSON, default=dict)
    sandbox_analysis: Mapped[dict] = mapped_column(JSON, default=dict)
    ml_analysis: Mapped[dict] = mapped_column(JSON, default=dict)
    yara_matches: Mapped[list] = mapped_column(JSON, default=list)
    behavior: Mapped[dict] = mapped_column(JSON, default=dict)
    iocs: Mapped[dict] = mapped_column(JSON, default=dict)
    timeline: Mapped[list] = mapped_column(JSON, default=list)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
# Project version: ThreatVault V1.2
