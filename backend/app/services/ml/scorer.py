"""ML scoring engine — feature extraction + XGBoost/LightGBM classifier."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np

from app.core.config import get_settings
from app.models.schemas import MLResult, SandboxResult, StaticAnalysisResult

SUSPICIOUS_APIS = {
    "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread", "URLDownloadToFile",
    "RegSetValue", "CryptEncrypt", "IsDebuggerPresent", "ShellExecute",
}

FEATURE_NAMES = [
    "entropy",
    "max_section_entropy",
    "entropy_variance",
    "import_count",
    "suspicious_api_ratio",
    "export_count",
    "string_count",
    "suspicious_string_ratio",
    "packer_count",
    "indicator_count",
    "process_count",
    "network_call_count",
    "file_write_count",
    "registry_change_count",
]


def extract_features(static: StaticAnalysisResult, sandbox: SandboxResult | None = None) -> dict[str, float]:
    section_values = list(static.section_entropies.values()) or [static.entropy]
    import_count = len(static.imports)
    suspicious_imports = sum(
        1 for imp in static.imports if any(api in imp for api in SUSPICIOUS_APIS)
    )
    suspicious_strings = sum(
        1 for s in static.strings
        if any(k in s.lower() for k in ("http", "cmd", "powershell", "encrypt", "payload"))
    )
    string_count = max(len(static.strings), 1)

    features = {
        "entropy": static.entropy,
        "max_section_entropy": max(section_values),
        "entropy_variance": float(np.var(section_values)),
        "import_count": float(import_count),
        "suspicious_api_ratio": suspicious_imports / max(import_count, 1),
        "export_count": float(len(static.exports)),
        "string_count": float(string_count),
        "suspicious_string_ratio": suspicious_strings / string_count,
        "packer_count": float(len(static.packers)),
        "indicator_count": float(len(static.suspicious_indicators)),
        "process_count": float(len(sandbox.process_tree)) if sandbox else 1.0,
        "network_call_count": float(len(sandbox.network_calls)) if sandbox else 0.0,
        "file_write_count": float(
            sum(1 for op in sandbox.file_operations if op.get("action") == "write")
        ) if sandbox else 0.0,
        "registry_change_count": float(len(sandbox.registry_operations)) if sandbox else 0.0,
    }
    return features


def _heuristic_score(features: dict[str, float]) -> tuple[float, list[dict[str, Any]]]:
    weights = {
        "entropy": 0.12,
        "max_section_entropy": 0.10,
        "suspicious_api_ratio": 0.18,
        "suspicious_string_ratio": 0.10,
        "packer_count": 0.08,
        "indicator_count": 0.12,
        "process_count": 0.08,
        "network_call_count": 0.10,
        "file_write_count": 0.06,
        "registry_change_count": 0.06,
    }

    contributors: list[dict[str, Any]] = []
    score = 0.0
    for name, weight in weights.items():
        value = features.get(name, 0.0)
        normalized = min(value / (1.0 if name.endswith("_ratio") else 10.0), 1.0)
        contribution = normalized * weight * 100
        score += contribution
        if contribution > 2:
            contributors.append({"feature": name, "value": value, "contribution": round(contribution, 2)})

    contributors.sort(key=lambda x: x["contribution"], reverse=True)
    return min(score, 100.0), contributors[:5]


def _load_xgboost_model(model_path: Path):
    try:
        import xgboost as xgb

        if model_path.exists():
            booster = xgb.Booster()
            booster.load_model(str(model_path))
            return ("xgboost", booster)
    except Exception:
        pass

    try:
        import lightgbm as lgb

        lgb_path = model_path.with_suffix(".lgb")
        if lgb_path.exists():
            return ("lightgbm", lgb.Booster(model_file=str(lgb_path)))
    except Exception:
        pass

    return None


def score_sample(
    static: StaticAnalysisResult,
    sandbox: SandboxResult | None = None,
) -> MLResult:
    settings = get_settings()
    features = extract_features(static, sandbox)
    feature_vector = np.array([[features[name] for name in FEATURE_NAMES]])

    model_info = _load_xgboost_model(settings.ml_model_path) if settings.enable_ml else None

    if model_info:
        model_name, model = model_info
        if model_name == "xgboost":
            import xgboost as xgb

            dmatrix = xgb.DMatrix(feature_vector, feature_names=FEATURE_NAMES)
            prob = float(model.predict(dmatrix)[0])
        else:
            prob = float(model.predict(feature_vector)[0])

        contributors = [
            {"feature": name, "value": features[name], "contribution": round(features[name] * prob * 10, 2)}
            for name in FEATURE_NAMES
        ]
        contributors.sort(key=lambda x: x["contribution"], reverse=True)

        return MLResult(
            model=model_name,
            probability_malicious=round(prob, 4),
            features=features,
            top_contributors=contributors[:5],
        )

    heuristic, contributors = _heuristic_score(features)
    return MLResult(
        model="heuristic_v1",
        probability_malicious=round(heuristic / 100, 4),
        features=features,
        top_contributors=contributors,
    )


def compute_risk_score(
    static: StaticAnalysisResult,
    sandbox: SandboxResult | None,
    ml: MLResult,
    yara_count: int = 0,
) -> tuple[float, list[str]]:
    flags: list[str] = []

    if ml.probability_malicious >= 0.7:
        flags.append("high_ml_confidence")
    if static.entropy > 7.2:
        flags.append("high_entropy")
    if static.packers:
        flags.append("packed_executable")
    if "suspicious_imports" in static.suspicious_indicators:
        flags.append("suspicious_imports")
    if "obfuscated_strings" in static.suspicious_indicators:
        flags.append("obfuscated_strings")
    if sandbox:
        if len(sandbox.process_tree) > 2:
            flags.append("injects_process")
        if sandbox.network_calls:
            flags.append("suspicious_network")
        if sandbox.registry_operations:
            flags.append("persistence_registry")
        if any(op.get("action") == "write" for op in sandbox.file_operations):
            flags.append("drops_files")
        if sandbox.verdict == "malicious":
            flags.append("sandbox_malicious")
    if yara_count > 0:
        flags.append("yara_match")

    base = ml.probability_malicious * 70
    static_boost = len(static.suspicious_indicators) * 5
    sandbox_boost = 0
    if sandbox:
        sandbox_boost = {"malicious": 20, "suspicious": 12, "likely_suspicious": 6}.get(sandbox.verdict, 0)
    yara_boost = min(yara_count * 8, 24)

    risk = min(base + static_boost + sandbox_boost + yara_boost, 100.0)
    return round(risk, 1), flags
# Project version: ThreatVault V1.2
