from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ScanStatus(str, Enum):
    pending = "pending"
    static = "static_analysis"
    sandbox = "sandbox_running"
    ml = "ml_scoring"
    completed = "completed"
    failed = "failed"
    cached = "cached"


class BehaviorReport(BaseModel):
    processes: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    file_writes: list[str] = Field(default_factory=list)
    registry_changes: list[str] = Field(default_factory=list)
    network_connections: list[dict[str, Any]] = Field(default_factory=list)


class StaticAnalysisResult(BaseModel):
    file_type: str
    architecture: str | None = None
    entropy: float
    section_entropies: dict[str, float] = Field(default_factory=dict)
    strings: list[str] = Field(default_factory=list)
    imports: list[str] = Field(default_factory=list)
    exports: list[str] = Field(default_factory=list)
    packers: list[str] = Field(default_factory=list)
    suspicious_indicators: list[str] = Field(default_factory=list)
    headers: dict[str, Any] = Field(default_factory=dict)


class SandboxResult(BaseModel):
    duration_seconds: float
    process_tree: list[dict[str, Any]] = Field(default_factory=list)
    network_calls: list[dict[str, Any]] = Field(default_factory=list)
    file_operations: list[dict[str, Any]] = Field(default_factory=list)
    registry_operations: list[dict[str, Any]] = Field(default_factory=list)
    screenshots: list[str] = Field(default_factory=list)
    verdict: str = "unknown"


class MLResult(BaseModel):
    model: str
    probability_malicious: float
    features: dict[str, float] = Field(default_factory=dict)
    top_contributors: list[dict[str, Any]] = Field(default_factory=list)


class YaraMatch(BaseModel):
    rule: str
    namespace: str
    tags: list[str] = Field(default_factory=list)
    meta: dict[str, Any] = Field(default_factory=list)
    strings: list[str] = Field(default_factory=list)


class TimelineEvent(BaseModel):
    timestamp: float
    phase: str
    event: str
    details: dict[str, Any] = Field(default_factory=dict)


class IOCReport(BaseModel):
    hashes: dict[str, str] = Field(default_factory=dict)
    domains: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    file_paths: list[str] = Field(default_factory=list)
    registry_keys: list[str] = Field(default_factory=list)


class AnalysisReport(BaseModel):
    id: str
    sha256: str
    md5: str
    filename: str
    file_size: int
    status: ScanStatus
    risk_score: float
    flags: list[str]
    behavior: BehaviorReport
    static_analysis: StaticAnalysisResult | dict[str, Any] | None = None
    sandbox_analysis: SandboxResult | dict[str, Any] | None = None
    ml_analysis: MLResult | dict[str, Any] | None = None
    yara_matches: list[YaraMatch | dict[str, Any]] = Field(default_factory=list)
    iocs: IOCReport | dict[str, Any] | None = None
    timeline: list[TimelineEvent | dict[str, Any]] = Field(default_factory=list)
    created_at: datetime
    completed_at: datetime | None = None

    model_config = {"from_attributes": True}


class ScanResponse(BaseModel):
    scan_id: str
    sha256: str
    status: ScanStatus
    message: str
    cached: bool = False


class PlatformStats(BaseModel):
    total_scans: int
    completed_scans: int
    high_risk_samples: int
    cache_hits: int
    avg_risk_score: float
    top_flags: list[dict[str, Any]]
# Project version: ThreatVault V1.1
