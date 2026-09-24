"""Native release identities and binary-format checks, independent of build-host tools."""

from __future__ import annotations

import json
from pathlib import Path
import re
import struct

from release_lib import ReleaseError

ROOT = Path(__file__).resolve().parents[2]


def platforms() -> dict[str, dict[str, str]]:
    inventory = json.loads((ROOT / "sdk/native-platforms.v1.json").read_bytes())
    if inventory.get("schema") != "cigar.native-platforms.v1":
        raise ReleaseError("invalid native platform inventory")
    result = {entry["id"]: entry for entry in inventory["platforms"]}
    if len(result) != len(inventory["platforms"]):
        raise ReleaseError("duplicate native platform")
    return result


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ReleaseError(message)


def _cstring(data: bytes, offset: int) -> str:
    _require(0 <= offset < len(data), "binary string offset outside file")
    end = data.find(b"\0", offset, offset + 4096)
    _require(end >= 0, "unterminated native dependency name")
    try:
        return data[offset:end].decode("ascii")
    except UnicodeDecodeError as error:
        raise ReleaseError("non-ASCII native dependency name") from error


def inspect_binary(path: Path, identity: str) -> dict:
    """Check architecture, dynamic dependencies and the declared deployment floor.

    This is a format/ABI check. Runtime qualification must execute the installed
    worker on the corresponding platform; successful parsing is not that evidence.
    """
    _require(identity in platforms(), "undeclared native platform")
    _require(
        path.is_file() and not path.is_symlink(), "native binary must be a regular file"
    )
    data = path.read_bytes()
    _require(64 <= len(data) <= 64 * 1024 * 1024, "native binary size outside bounds")
    try:
        if identity.startswith("darwin-"):
            return _macho(data, identity)
        if identity.startswith("linux-"):
            return _elf(data, identity)
        return _pe(data, identity)
    except (struct.error, IndexError, OverflowError) as error:
        raise ReleaseError("truncated or malformed native binary") from error


def _macho(data: bytes, identity: str) -> dict:
    _require(data[:4] == b"\xcf\xfa\xed\xfe", "expected thin little-endian Mach-O 64")
    (cpu,) = struct.unpack_from("<I", data, 4)
    expected = 0x0100000C if identity == "darwin-arm64" else 0x01000007
    _require(cpu == expected, "Mach-O architecture differs from platform")
    count, size = struct.unpack_from("<II", data, 16)
    _require(count <= 4096 and 32 + size <= len(data), "invalid Mach-O command region")
    cursor = 32
    minimum = None
    needed = []
    for _ in range(count):
        command, length = struct.unpack_from("<II", data, cursor)
        _require(length >= 8 and cursor + length <= 32 + size, "invalid Mach-O command")
        if command == 0x32:
            platform, value = struct.unpack_from("<II", data, cursor + 8)
            _require(platform == 1, "Mach-O is not a macOS executable")
            minimum = (value >> 16, (value >> 8) & 255, value & 255)
        elif command == 0x24:
            (value,) = struct.unpack_from("<I", data, cursor + 8)
            minimum = (value >> 16, (value >> 8) & 255, value & 255)
        elif command & 0x7FFFFFFF in {0xC, 0x18, 0x1F, 0x23}:
            (offset,) = struct.unpack_from("<I", data, cursor + 8)
            _require(8 <= offset < length, "invalid Mach-O dependency offset")
            name = _cstring(data[: cursor + length], cursor + offset)
            _require(
                name.startswith(("/usr/lib/", "/System/Library/Frameworks/")),
                "non-system macOS dependency",
            )
            needed.append(name)
        cursor += length
    _require(cursor == 32 + size, "Mach-O commands do not cover declared region")
    _require(
        minimum is not None and minimum <= (11, 0, 0),
        "macOS deployment floor exceeds wheel tag",
    )
    return {
        "format": "macho64",
        "platform": identity,
        "minimum_os": list(minimum),
        "needed": sorted(needed),
    }


def _elf(data: bytes, identity: str) -> dict:
    _require(data[:6] == b"\x7fELF\x02\x01", "expected little-endian ELF64")
    (machine,) = struct.unpack_from("<H", data, 18)
    _require(
        machine == (183 if "-arm64-" in identity else 62),
        "ELF architecture differs from platform",
    )
    phoff, shoff = struct.unpack_from("<QQ", data, 32)
    phsize, phcount, shsize, shcount, strindex = struct.unpack_from("<HHHHH", data, 54)
    _require(
        phsize >= 56 and phcount <= 4096 and phoff + phsize * phcount <= len(data),
        "invalid ELF program headers",
    )
    _require(
        shsize >= 64 and shcount <= 65535 and shoff + shsize * shcount <= len(data),
        "invalid ELF sections",
    )
    interpreter = None
    for index in range(phcount):
        offset = phoff + phsize * index
        (kind,) = struct.unpack_from("<I", data, offset)
        if kind == 3:
            (start,) = struct.unpack_from("<Q", data, offset + 8)
            (length,) = struct.unpack_from("<Q", data, offset + 32)
            _require(
                start + length <= len(data) and length <= 4096,
                "invalid ELF interpreter",
            )
            interpreter = _cstring(data[: start + length], start)
    sections = [
        struct.unpack_from("<IIQQQQIIQQ", data, shoff + index * shsize)
        for index in range(shcount)
    ]
    _require(strindex < len(sections), "missing ELF section-name table")
    names_section = sections[strindex]
    names = data[names_section[4] : names_section[4] + names_section[5]]
    by_name = {_cstring(names, section[0]): section for section in sections}
    dynamic_strings = b""
    needed = []
    if ".dynstr" in by_name:
        section = by_name[".dynstr"]
        _require(section[4] + section[5] <= len(data), "invalid ELF dynamic strings")
        dynamic_strings = data[section[4] : section[4] + section[5]]
    if ".dynamic" in by_name:
        section = by_name[".dynamic"]
        _require(
            section[4] + section[5] <= len(data) and section[5] % 16 == 0,
            "invalid ELF dynamic table",
        )
        for position in range(section[4], section[4] + section[5], 16):
            kind, value = struct.unpack_from("<qQ", data, position)
            if kind == 1:
                needed.append(_cstring(dynamic_strings, value))
    versions = sorted(
        {
            tuple(map(int, match))
            for match in re.findall(rb"(?<!X)GLIBC_(\d+)\.(\d+)", dynamic_strings)
        }
    )
    if identity.endswith("-musl"):
        _require(
            interpreter is None and not needed and not versions,
            "musl worker must be statically linked",
        )
    else:
        expected = (
            "/lib/ld-linux-aarch64.so.1"
            if "-arm64-" in identity
            else "/lib64/ld-linux-x86-64.so.2"
        )
        _require(
            interpreter == expected, "GNU worker has an unexpected ELF interpreter"
        )
        _require(
            bool(versions) and max(versions) <= (2, 28),
            "glibc deployment floor exceeds manylinux tag",
        )
        allowed = {
            "libc.so.6",
            "libgcc_s.so.1",
            "libpthread.so.0",
            "libm.so.6",
            "libdl.so.2",
            "librt.so.1",
            "ld-linux-x86-64.so.2",
            "ld-linux-aarch64.so.1",
        }
        _require(
            set(needed) <= allowed, "GNU worker has an unbundled non-system dependency"
        )
    return {
        "format": "elf64",
        "platform": identity,
        "interpreter": interpreter,
        "needed": sorted(needed),
        "glibc_versions": [list(version) for version in versions],
    }


def _pe(data: bytes, identity: str) -> dict:
    _require(
        data[:2] == b"MZ" and identity == "win32-x64",
        "expected Windows x64 PE executable",
    )
    (pe,) = struct.unpack_from("<I", data, 0x3C)
    _require(data[pe : pe + 4] == b"PE\0\0", "invalid PE signature")
    machine, count = struct.unpack_from("<HH", data, pe + 4)
    _require(
        machine == 0x8664 and count <= 256, "PE architecture differs from platform"
    )
    (optional_size,) = struct.unpack_from("<H", data, pe + 20)
    optional = pe + 24
    (magic,) = struct.unpack_from("<H", data, optional)
    _require(magic == 0x20B and optional_size >= 224, "expected PE32+ optional header")
    sections = optional + optional_size

    def location(rva: int) -> int:
        for index in range(count):
            offset = sections + index * 40
            virtual_size, address, raw_size, raw = struct.unpack_from(
                "<IIII", data, offset + 8
            )
            if address <= rva < address + max(virtual_size, raw_size):
                result = raw + rva - address
                _require(result < len(data), "PE address outside file")
                return result
        raise ReleaseError("unmapped PE address")

    needed = []
    imports, size = struct.unpack_from("<II", data, optional + 120)
    if imports:
        position = location(imports)
        _require(size <= len(data), "invalid PE imports size")
        for _ in range(256):
            entry = struct.unpack_from("<IIIII", data, position)
            if not any(entry):
                break
            needed.append(_cstring(data, location(entry[3])).lower())
            position += 20
        else:
            raise ReleaseError("unbounded PE imports")
    allowed = {
        "kernel32.dll",
        "advapi32.dll",
        "userenv.dll",
        "ws2_32.dll",
        "bcrypt.dll",
        "ntdll.dll",
        "ole32.dll",
        "shell32.dll",
        "synchronization.dll",
        "ucrtbase.dll",
    }
    _require(
        all(name in allowed or name.startswith("api-ms-win-") for name in needed),
        "Windows worker requires a non-system DLL; use the static MSVC runtime",
    )
    (delayed,) = struct.unpack_from("<I", data, optional + 112 + 13 * 8)
    _require(delayed == 0, "unverified delayed Windows imports")
    return {"format": "pe64", "platform": identity, "needed": sorted(needed)}
