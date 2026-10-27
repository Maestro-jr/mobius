"""Native library hardening: what the .so files were, and were not, built with.

An Android app's native code is where a lot of the interesting behaviour hides,
and it is also where exploit mitigations are set or forgotten at build time. A
shared object with an executable stack, no RELRO, or no stack canaries is easier
to turn a memory bug into code execution against. None of that is visible from
the Java side, so this worker reads the ELF headers of every ``.so`` in the
decoded tree and reports which mitigations are present.

It runs in the sandbox like every other worker, reading ``/scan`` (the decoded
resources an earlier stage produced), never the APK. The ELF parsing is a small,
bounded, hand-rolled reader: it walks the program headers and the dynamic
section and never executes a byte of what it reads, so a hostile ``.so`` is a
few structs to parse, not code to run.

Output::

    { "ok": bool, "error": str|null, "tool": "nativelib",
      "libraries": [ { "path": str, "arch": str|null, "bits": 32|64,
                       "hardening": { "nx": bool, "relro": "none|partial|full",
                                      "stack_canary": bool, "fortify": bool,
                                      "executable_stack": bool } } ] }

The findings themselves are decided by the adapter from these facts, because
"an executable stack is a weakness" is a judgement and this worker only reports
what it saw.
"""
from __future__ import annotations

import json
import os
import struct
import sys
import traceback

SCAN_DIR = "/scan"
MAX_LIBS = 256
# Enough for the ELF header, the program headers, the dynamic section, and a
# window to scan for the stack-protector symbols. A .so is often larger, but
# the mitigations are all recorded near the start and in the dynamic segment.
MAX_BYTES = 4 * 1024 * 1024

# Program header types.
PT_DYNAMIC = 2
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552
PF_X = 0x1

# Dynamic tags.
DT_NULL = 0
DT_BIND_NOW = 24
DT_FLAGS = 30
DF_BIND_NOW = 0x8

# Symbols that betray a stack protector and fortified libc calls. A byte scan is
# a heuristic, and the adapter's finding says "no stack-protector symbols" rather
# than "unprotected", because the honest claim is about what was observed.
_CANARY = b"__stack_chk_fail"
_FORTIFY = (b"__memcpy_chk", b"__strcpy_chk", b"__sprintf_chk",
            b"__snprintf_chk", b"__memset_chk", b"__strcat_chk")


def clip(value, limit=1024):
    text = "" if value is None else str(value)
    return text[:limit]


def inspect_elf(data: bytes) -> dict | None:
    """The hardening facts of one ELF image, or None if it is not an ELF.

    Deliberately forgiving: a truncated or odd section returns what could be
    read rather than raising, because a report that drops a library on a parse
    quirk is worse than one that says "canary unknown" for it.
    """
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return None
    bits = 64 if data[4] == 2 else 32
    endian = "<" if data[5] == 1 else ">"

    try:
        if bits == 64:
            e_type = struct.unpack_from(endian + "H", data, 16)[0]
            e_phoff = struct.unpack_from(endian + "Q", data, 32)[0]
            e_phentsize = struct.unpack_from(endian + "H", data, 54)[0]
            e_phnum = struct.unpack_from(endian + "H", data, 56)[0]
        else:
            e_type = struct.unpack_from(endian + "H", data, 16)[0]
            e_phoff = struct.unpack_from(endian + "I", data, 28)[0]
            e_phentsize = struct.unpack_from(endian + "H", data, 42)[0]
            e_phnum = struct.unpack_from(endian + "H", data, 44)[0]
    except struct.error:
        return {"bits": bits, "type": None, "nx": True, "relro": "none",
                "stack_canary": False, "fortify": False,
                "executable_stack": False}

    executable_stack = False
    has_gnu_stack = False
    has_relro = False
    bind_now = False

    for index in range(min(e_phnum, 128)):
        base = e_phoff + index * e_phentsize
        if base + e_phentsize > len(data):
            break
        p_type = struct.unpack_from(endian + "I", data, base)[0]
        if bits == 64:
            p_flags = struct.unpack_from(endian + "I", data, base + 4)[0]
            p_offset = struct.unpack_from(endian + "Q", data, base + 8)[0]
            p_filesz = struct.unpack_from(endian + "Q", data, base + 32)[0]
        else:
            p_offset = struct.unpack_from(endian + "I", data, base + 4)[0]
            p_filesz = struct.unpack_from(endian + "I", data, base + 16)[0]
            p_flags = struct.unpack_from(endian + "I", data, base + 24)[0]

        if p_type == PT_GNU_STACK:
            has_gnu_stack = True
            executable_stack = bool(p_flags & PF_X)
        elif p_type == PT_GNU_RELRO:
            has_relro = True
        elif p_type == PT_DYNAMIC:
            bind_now = bind_now or _dynamic_bind_now(
                data, p_offset, p_filesz, bits, endian)

    if has_relro and bind_now:
        relro = "full"
    elif has_relro:
        relro = "partial"
    else:
        relro = "none"

    canary = _CANARY in data
    fortify = any(symbol in data for symbol in _FORTIFY)

    return {
        "bits": bits,
        "type": e_type,
        # An absent GNU_STACK is left as NX true: modern Android maps the stack
        # non-executable by default, so only an explicitly executable one is a
        # finding. has_gnu_stack is kept so a reader can tell the two apart.
        "nx": not executable_stack,
        "executable_stack": executable_stack,
        "has_gnu_stack": has_gnu_stack,
        "relro": relro,
        "stack_canary": canary,
        "fortify": fortify,
    }


def _dynamic_bind_now(data, offset, size, bits, endian) -> bool:
    """Whether the dynamic section asks the loader to bind eagerly (full RELRO)."""
    entry = 16 if bits == 64 else 8
    end = min(offset + size, len(data))
    pos = offset
    fmt = endian + ("Q" if bits == 64 else "I")
    while pos + entry <= end:
        try:
            tag = struct.unpack_from(fmt, data, pos)[0]
            val = struct.unpack_from(fmt, data, pos + (8 if bits == 64 else 4))[0]
        except struct.error:
            break
        if tag == DT_NULL:
            break
        if tag == DT_BIND_NOW:
            return True
        if tag == DT_FLAGS and (val & DF_BIND_NOW):
            return True
        pos += entry
    return False


def _arch_of(path: str) -> str | None:
    parts = path.replace("\\", "/").split("/")
    for i, part in enumerate(parts):
        if part == "lib" and i + 1 < len(parts):
            return parts[i + 1]
    return None


def scan(root: str) -> list[dict]:
    libraries: list[dict] = []
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            if not name.endswith(".so"):
                continue
            if len(libraries) >= MAX_LIBS:
                return libraries
            full = os.path.join(dirpath, name)
            try:
                with open(full, "rb") as handle:
                    data = handle.read(MAX_BYTES)
            except OSError:
                continue
            hardening = inspect_elf(data)
            if hardening is None:
                continue
            rel = os.path.relpath(full, root).replace("\\", "/")
            libraries.append({
                "path": clip(rel),
                "name": clip(name, 255),
                "arch": _arch_of(rel),
                "bits": hardening.pop("bits", None),
                "hardening": hardening,
            })
    return sorted(libraries, key=lambda entry: entry["path"])


def main() -> int:
    try:
        if not os.path.isdir(SCAN_DIR):
            print(json.dumps({"ok": False, "tool": "nativelib",
                              "error": "nothing to scan: /scan was not mounted",
                              "libraries": []}))
            return 0
        libraries = scan(SCAN_DIR)
        print(json.dumps({"ok": True, "tool": "nativelib", "error": None,
                          "libraries": libraries}))
        return 0
    except Exception as exc:                            # noqa: BLE001
        print(json.dumps({"ok": False, "tool": "nativelib",
                          "error": clip(f"{type(exc).__name__}: {exc}", 2000),
                          "trace": clip(traceback.format_exc(), 4000),
                          "libraries": []}))
        return 0


if __name__ == "__main__":
    sys.exit(main())
