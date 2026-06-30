#!/usr/bin/env python3
"""Generate a safe, benign demo sample for ThreatVault public testing."""

from pathlib import Path

SAMPLE = b"MZ" + b"\x00" * 58 + b"\x40\x00" + b"\x00" * 200
SAMPLE += b"ThreatVault public portfolio demo sample\r\n"
SAMPLE += b"This file is benign metadata for UI and static-analysis previews.\r\n"
SAMPLE += b"No payload, exploit, persistence, credential or destructive behavior is included.\r\n"
SAMPLE += b"KRYNEX Labs defensive-only demo artifact\r\n"
SAMPLE += bytes([i % 127 for i in range(2048)])

out = Path(__file__).parent.parent / "samples" / "safe_demo_sample.bin"
out.parent.mkdir(exist_ok=True)
out.write_bytes(SAMPLE)
print(f"Created safe demo sample: {out} ({len(SAMPLE)} bytes)")
# Project version: ThreatVault V1.2
