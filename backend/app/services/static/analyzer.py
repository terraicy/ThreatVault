"""Static analysis — PE/ELF headers, entropy, strings, imports, packer detection."""

from __future__ import annotations

import math
import re
import struct
from pathlib import Path
from typing import Any

from app.models.schemas import StaticAnalysisResult

SUSPICIOUS_APIS = {
    "VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "CreateRemoteThread",
    "NtUnmapViewOfSection", "SetWindowsHookEx", "GetProcAddress", "LoadLibraryA",
    "WinExec", "ShellExecute", "URLDownloadToFile", "InternetOpen", "InternetReadFile",
    "RegSetValue", "RegCreateKey", "CryptEncrypt", "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
}

PACKER_SIGNATURES = {
    b"UPX0": "UPX",
    b"UPX1": "UPX",
    b".UPX": "UPX",
    b"ASPack": "ASPack",
    b"PECompact": "PECompact",
    b"Themida": "Themida",
    b"VMProtect": "VMProtect",
    b".vmp": "VMProtect",
    b"MPRESS": "MPRESS",
    b"FSG!": "FSG",
}

SUSPICIOUS_STRINGS = re.compile(
    r"(cmd\.exe|powershell|wget|curl|/bin/sh|/bin/bash|"
    r"CreateRemoteThread|VirtualAlloc|http://|https://|"
    r"\.onion|bitcoin|ransom|encrypt|decrypt|payload|"
    r"shellcode|inject|backdoor|keylog|exfil)",
    re.IGNORECASE,
)


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq if c)


def _extract_ascii_strings(data: bytes, min_len: int = 6) -> list[str]:
    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    found = pattern.findall(data)
    return [s.decode("ascii", errors="ignore") for s in found[:500]]


def _detect_packers(data: bytes) -> list[str]:
    detected: set[str] = set()
    for sig, name in PACKER_SIGNATURES.items():
        if sig in data:
            detected.add(name)
    return sorted(detected)


def _analyze_pe(data: bytes) -> dict[str, Any]:
    import pefile

    pe = pefile.PE(data=data, fast_load=True)
    pe.parse_data_directories(
        directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
        ]
    )

    section_entropies: dict[str, float] = {}
    for section in pe.sections:
        name = section.Name.decode("utf-8", errors="ignore").strip("\x00")
        section_entropies[name or f"section_{section.VirtualAddress:x}"] = section.get_entropy()

    imports: list[str] = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT") and pe.DIRECTORY_ENTRY_IMPORT:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("utf-8", errors="ignore")
            for imp in entry.imports:
                if imp.name:
                    imports.append(f"{dll}!{imp.name.decode('utf-8', errors='ignore')}")

    exports: list[str] = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") and pe.DIRECTORY_ENTRY_EXPORT:
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                exports.append(exp.name.decode("utf-8", errors="ignore"))

    machine = pe.FILE_HEADER.Machine
    arch_map = {0x014C: "x86", 0x8664: "x64", 0xAA64: "ARM64"}
    architecture = arch_map.get(machine, hex(machine))

    headers = {
        "machine": architecture,
        "timestamp": pe.FILE_HEADER.TimeDateStamp,
        "sections": len(pe.sections),
        "subsystem": pe.OPTIONAL_HEADER.Subsystem,
        "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
        "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
    }

    pe.close()
    return {
        "file_type": "PE",
        "architecture": architecture,
        "section_entropies": section_entropies,
        "imports": imports,
        "exports": exports,
        "headers": headers,
    }


def _analyze_elf(data: bytes) -> dict[str, Any]:
    from elftools.elf.elffile import ELFFile
    from io import BytesIO

    elf = ELFFile(BytesIO(data))
    imports: list[str] = []
    exports: list[str] = []

    dynsym = elf.get_section_by_name(".dynsym")
    if dynsym:
        for sym in dynsym.iter_symbols():
            if sym["st_info"]["type"] == "STT_FUNC" and sym.name:
                if sym["st_shndx"] == "SHN_UNDEF":
                    imports.append(sym.name)
                else:
                    exports.append(sym.name)

    section_entropies: dict[str, float] = {}
    for section in elf.iter_sections():
        sec_data = section.data()
        if sec_data:
            section_entropies[section.name] = _shannon_entropy(sec_data)

    return {
        "file_type": "ELF",
        "architecture": elf.get_machine_arch(),
        "section_entropies": section_entropies,
        "imports": imports[:200],
        "exports": exports[:200],
        "headers": {
            "class": elf.elfclass,
            "type": elf.header["e_type"],
            "entry_point": hex(elf.header["e_entry"]),
            "sections": elf.num_sections(),
        },
    }


def _detect_file_type(data: bytes) -> str:
    if len(data) >= 2 and data[:2] == b"MZ":
        return "PE"
    if len(data) >= 4 and data[:4] == b"\x7fELF":
        return "ELF"
    if data[:4] == b"\xca\xfe\xba\xbe" or data[:4] == b"\xce\xfa\xed\xfe":
        return "Mach-O"
    if data[:2] == b"PK":
        return "ZIP/Office"
    return "unknown"


def analyze_static(data: bytes, filename: str = "") -> StaticAnalysisResult:
    file_type = _detect_file_type(data)
    entropy = _shannon_entropy(data)
    strings = _extract_ascii_strings(data)
    packers = _detect_packers(data)

    section_entropies: dict[str, float] = {}
    imports: list[str] = []
    exports: list[str] = []
    headers: dict[str, Any] = {}
    architecture: str | None = None

    try:
        if file_type == "PE":
            pe_info = _analyze_pe(data)
            section_entropies = pe_info["section_entropies"]
            imports = pe_info["imports"]
            exports = pe_info["exports"]
            headers = pe_info["headers"]
            architecture = pe_info["architecture"]
            file_type = "PE"
        elif file_type == "ELF":
            elf_info = _analyze_elf(data)
            section_entropies = elf_info["section_entropies"]
            imports = elf_info["imports"]
            exports = elf_info["exports"]
            headers = elf_info["headers"]
            architecture = elf_info["architecture"]
    except Exception as exc:
        headers["parse_error"] = str(exc)

    suspicious: list[str] = []
    if entropy > 7.2:
        suspicious.append("high_entropy")
    high_entropy_sections = [s for s, e in section_entropies.items() if e > 7.5]
    if high_entropy_sections:
        suspicious.append("encrypted_sections")
    if packers:
        suspicious.append("packer_detected")

    suspicious_apis = [i for i in imports if any(api in i for api in SUSPICIOUS_APIS)]
    if suspicious_apis:
        suspicious.append("suspicious_imports")

    suspicious_strings = [s for s in strings if SUSPICIOUS_STRINGS.search(s)]
    if suspicious_strings:
        suspicious.append("suspicious_strings")

    if len(strings) < 5 and len(data) > 10000:
        suspicious.append("obfuscated_strings")

    return StaticAnalysisResult(
        file_type=file_type,
        architecture=architecture,
        entropy=round(entropy, 4),
        section_entropies={k: round(v, 4) for k, v in section_entropies.items()},
        strings=strings[:100],
        imports=imports[:150],
        exports=exports[:50],
        packers=packers,
        suspicious_indicators=suspicious,
        headers=headers,
    )
# Project version: ThreatVault V1.2
