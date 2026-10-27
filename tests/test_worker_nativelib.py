"""The nativelib worker's ELF reader, tested outside the container.

The parsing is the part most likely to be wrong, and it runs on hostile input,
so it is exercised directly here with hand-built ELF images rather than waiting
for a Docker run. Each test constructs a 64-bit little-endian ELF with the
program headers that decide one mitigation, and asserts the reader reports it.
"""
from __future__ import annotations

import importlib.util
import struct
import sys
from pathlib import Path

import pytest

_WORKER = (Path(__file__).resolve().parent.parent
           / "workers" / "nativelib" / "analyze.py")

PT_DYNAMIC = 2
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552


@pytest.fixture(scope="module")
def worker():
    spec = importlib.util.spec_from_file_location("themob_nativelib_worker",
                                                  _WORKER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _elf64(phdrs, extra=b"") -> bytes:
    """A 64-bit LE ELF with the given program headers and trailing bytes.

    phdrs: list of (p_type, p_flags, p_offset, p_filesz).
    """
    ehsize, phentsize = 64, 56
    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4] = 2                                         # 64-bit
    header[5] = 1                                         # little-endian
    header[6] = 1
    struct.pack_into("<H", header, 16, 3)                # ET_DYN
    struct.pack_into("<H", header, 18, 0xB7)             # aarch64
    struct.pack_into("<I", header, 20, 1)
    struct.pack_into("<Q", header, 32, ehsize)           # e_phoff
    struct.pack_into("<H", header, 52, ehsize)
    struct.pack_into("<H", header, 54, phentsize)
    struct.pack_into("<H", header, 56, len(phdrs))

    table = bytearray()
    for p_type, p_flags, p_offset, p_filesz in phdrs:
        entry = bytearray(56)
        struct.pack_into("<I", entry, 0, p_type)
        struct.pack_into("<I", entry, 4, p_flags)
        struct.pack_into("<Q", entry, 8, p_offset)
        struct.pack_into("<Q", entry, 32, p_filesz)
        table += entry
    return bytes(header) + bytes(table) + extra


# ------------------------------------------------------------------ not an elf

def test_a_non_elf_is_ignored(worker) -> None:
    assert worker.inspect_elf(b"MZ this is a PE" * 10) is None
    assert worker.inspect_elf(b"too short") is None


# ------------------------------------------------------------------ the stack

def test_an_executable_stack_is_detected(worker) -> None:
    elf = _elf64([(PT_GNU_STACK, 0x7, 0, 0)])            # RWX
    hardening = worker.inspect_elf(elf)
    assert hardening["executable_stack"] is True
    assert hardening["nx"] is False


def test_a_non_executable_stack_reads_as_nx(worker) -> None:
    elf = _elf64([(PT_GNU_STACK, 0x6, 0, 0)])            # RW
    hardening = worker.inspect_elf(elf)
    assert hardening["executable_stack"] is False
    assert hardening["nx"] is True


# ------------------------------------------------------------------- the relro

def test_no_relro_segment_is_none(worker) -> None:
    assert worker.inspect_elf(_elf64([(PT_GNU_STACK, 0x6, 0, 0)]))["relro"] \
        == "none"


def test_a_relro_segment_alone_is_partial(worker) -> None:
    elf = _elf64([(PT_GNU_RELRO, 0x4, 0, 0)])
    assert worker.inspect_elf(elf)["relro"] == "partial"


def test_relro_with_bind_now_is_full(worker) -> None:
    dynamic = struct.pack("<QQ", 24, 0) + struct.pack("<QQ", 0, 0)  # BIND_NOW, NULL
    base = 64 + 56 * 2
    elf = _elf64([(PT_GNU_RELRO, 0x4, 0, 0),
                  (PT_DYNAMIC, 0x6, base, len(dynamic))], extra=dynamic)
    assert worker.inspect_elf(elf)["relro"] == "full"


# --------------------------------------------------------------- the symbols

def test_the_canary_and_fortify_symbols_are_found(worker) -> None:
    elf = _elf64([(PT_GNU_STACK, 0x6, 0, 0)],
                 extra=b"\x00__stack_chk_fail\x00__memcpy_chk\x00")
    hardening = worker.inspect_elf(elf)
    assert hardening["stack_canary"] is True
    assert hardening["fortify"] is True


def test_no_symbols_reads_as_absent(worker) -> None:
    hardening = worker.inspect_elf(_elf64([(PT_GNU_STACK, 0x6, 0, 0)]))
    assert hardening["stack_canary"] is False
    assert hardening["fortify"] is False


# ------------------------------------------------------------------ the walk

def test_scan_walks_the_tree_and_keys_by_arch(worker, tmp_path) -> None:
    lib = tmp_path / "apktool" / "shop" / "lib" / "arm64-v8a"
    lib.mkdir(parents=True)
    (lib / "libfoo.so").write_bytes(_elf64([(PT_GNU_STACK, 0x7, 0, 0)]))
    (lib / "notelf.so").write_bytes(b"not an elf at all")
    (tmp_path / "readme.txt").write_text("ignored", encoding="utf-8")

    libraries = worker.scan(str(tmp_path))
    assert len(libraries) == 1                            # the non-ELF is dropped
    entry = libraries[0]
    assert entry["path"].endswith("lib/arm64-v8a/libfoo.so")
    assert entry["arch"] == "arm64-v8a"
    assert entry["hardening"]["executable_stack"] is True
