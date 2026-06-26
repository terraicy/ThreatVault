#!/usr/bin/env python3
"""Generate a safe demo PE-like sample for ThreatVault testing (not real malware)."""

from pathlib import Path

SAMPLE = b"MZ" + b"\x00" * 58 + b"\x40\x00" + b"\x00" * 200
SAMPLE += b"powershell -enc SQBFAFgA demo payload for ThreatVault analysis\r\n"
SAMPLE += b"VirtualAlloc WriteProcessMemory CreateRemoteThread\r\n"
SAMPLE += b"http://evil-c2.example.com/payload\r\n"
SAMPLE += b"URLDownloadToFile InternetOpen\r\n"
SAMPLE += b"ransom bitcoin decrypt .encrypted\r\n"
SAMPLE += b"UPX0 UPX1 packed section demo\r\n"
# Pad to look like a real-ish binary
SAMPLE += bytes([i % 256 for i in range(8000)])

out = Path(__file__).parent / "samples" / "demo_malware_sample.bin"
out.parent.mkdir(exist_ok=True)
out.write_bytes(SAMPLE)
print(f"Created demo sample: {out} ({len(SAMPLE)} bytes)")
