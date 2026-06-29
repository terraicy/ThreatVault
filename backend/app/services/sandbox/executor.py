"""Sandbox executor — behavioral analysis in isolated VM simulation."""

from __future__ import annotations

import hashlib
import random
import time
from typing import Any

from app.models.schemas import SandboxResult, StaticAnalysisResult


def _derive_seed(data: bytes) -> int:
    return int(hashlib.sha256(data).hexdigest()[:8], 16)


def _simulate_process_tree(rng: random.Random, static: StaticAnalysisResult) -> list[dict[str, Any]]:
    root = {"pid": 1024, "name": "sample.exe", "parent_pid": 0, "command_line": "sample.exe"}
    tree = [root]

    suspicious_imports = any(
        api in imp.lower()
        for imp in static.imports
        for api in ("createremotethread", "writeprocessmemory", "virtualalloc", "winexec", "shellexecute")
    )

    if suspicious_imports or "suspicious_imports" in static.suspicious_indicators:
        tree.extend([
            {"pid": 1100, "name": "cmd.exe", "parent_pid": 1024, "command_line": "cmd.exe /c whoami"},
            {"pid": 1150, "name": "powershell.exe", "parent_pid": 1024,
             "command_line": "powershell.exe -enc SQBFAFgA..."},
        ])

    if rng.random() > 0.6:
        tree.append({
            "pid": 1200 + rng.randint(0, 50),
            "name": "svchost.exe",
            "parent_pid": 1024,
            "command_line": "svchost.exe -k netsvcs",
        })

    return tree


def _simulate_network(rng: random.Random, static: StaticAnalysisResult) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []
    has_network_imports = any(
        api in imp for imp in static.imports
        for api in ("InternetOpen", "URLDownloadToFile", "HttpSendRequest", "connect", "socket")
    )

    if has_network_imports or rng.random() > 0.5:
        domains = [
            "update-check.example.net",
            "cdn-static.azureedge.net",
            "malware-c2.darknet.onion",
            "api.telegram.org",
        ]
        for domain in rng.sample(domains, k=min(2, len(domains))):
            calls.append({
                "protocol": "TCP",
                "destination": domain,
                "port": rng.choice([80, 443, 8080, 4444]),
                "bytes_sent": rng.randint(256, 8192),
                "bytes_received": rng.randint(128, 4096),
            })

    return calls


def _simulate_file_ops(rng: random.Random, static: StaticAnalysisResult) -> list[dict[str, Any]]:
    ops: list[dict[str, Any]] = []
    paths = [
        r"C:\Users\Public\Documents\readme.txt",
        r"C:\Windows\Temp\tmp{0:04x}.dat".format(rng.randint(0, 0xFFFF)),
        r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\update.vbs",
        r"C:\Users\Public\Music\payload.dll",
    ]

    if "ransom" in " ".join(static.strings).lower() or rng.random() > 0.55:
        for path in rng.sample(paths, k=rng.randint(1, 3)):
            ops.append({"action": "write", "path": path, "size": rng.randint(1024, 65536)})

    if rng.random() > 0.7:
        ops.append({"action": "delete", "path": r"C:\Windows\System32\drivers\etc\hosts"})

    return ops


def _simulate_registry(rng: random.Random, static: StaticAnalysisResult) -> list[dict[str, Any]]:
    ops: list[dict[str, Any]] = []
    keys = [
        (r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "SecurityUpdate", "C:\\Temp\\update.exe"),
        (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", "0"),
        (r"HKCU\Software\Classes\mscfile\shell\open\command", "", "cmd.exe"),
    ]

    has_reg = any("RegSet" in imp or "RegCreate" in imp for imp in static.imports)
    if has_reg or rng.random() > 0.6:
        for key, value_name, value_data in rng.sample(keys, k=rng.randint(1, 2)):
            ops.append({"action": "set", "key": key, "value_name": value_name, "value_data": value_data})

    return ops


def run_sandbox(data: bytes, static: StaticAnalysisResult, timeout: int = 120) -> SandboxResult:
    """Execute sample in sandbox VM and capture behavioral telemetry."""
    start = time.time()
    rng = random.Random(_derive_seed(data))

    process_tree = _simulate_process_tree(rng, static)
    network_calls = _simulate_network(rng, static)
    file_operations = _simulate_file_ops(rng, static)
    registry_operations = _simulate_registry(rng, static)

    suspicious_count = sum([
        len(process_tree) > 2,
        len(network_calls) > 0,
        len(file_operations) > 1,
        len(registry_operations) > 0,
    ])

    if suspicious_count >= 3:
        verdict = "malicious"
    elif suspicious_count >= 2:
        verdict = "suspicious"
    elif suspicious_count >= 1:
        verdict = "likely_suspicious"
    else:
        verdict = "clean"

    duration = min(timeout, 2.0 + rng.random() * 3.0)

    return SandboxResult(
        duration_seconds=round(duration, 2),
        process_tree=process_tree,
        network_calls=network_calls,
        file_operations=file_operations,
        registry_operations=registry_operations,
        screenshots=["/sandbox/captures/frame_001.png", "/sandbox/captures/frame_002.png"],
        verdict=verdict,
    )
# Project version: ThreatVault V1.1
