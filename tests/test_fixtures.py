"""The generated APK fixture is structurally sound.

The AXML encoder is test infrastructure the rest of the suite depends on, so it
gets checked independently: if it silently produced malformed chunks, the
androguard integration test would fail for the wrong reason.
"""
from __future__ import annotations

import struct
import zipfile
from pathlib import Path

from tests.fixtures.apk import PACKAGE, VERSION_NAME, build_apk, build_manifest
from tests.fixtures.axml import ANDROID_NS, encode_manifest

_RES_XML_TYPE = 0x0003
_RES_STRING_POOL_TYPE = 0x0001
_RES_XML_RESOURCE_MAP_TYPE = 0x0180
_START_ELEMENT = 0x0102
_END_ELEMENT = 0x0103


def _chunks(data: bytes, offset: int, end: int):
    """Walk the chunk framing, yielding ``(type, size, chunk_start)``.

    The offset yielded is the start of the chunk, not of its body: a string
    pool keeps its counts inside the header, so callers need the chunk origin.
    """
    while offset < end:
        chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", data, offset)
        assert chunk_size >= 8, "a chunk cannot be smaller than its header"
        assert header_size >= 8, "a header cannot be smaller than the chunk tag"
        assert offset + chunk_size <= end, "chunk overruns the file"
        yield chunk_type, chunk_size, offset
        offset += chunk_size


def test_manifest_framing_is_wellformed() -> None:
    data = encode_manifest(build_manifest())
    chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", data, 0)
    assert chunk_type == _RES_XML_TYPE
    assert header_size == 8
    assert chunk_size == len(data), "the root chunk must cover the whole file"

    types = [t for t, _size, _start in _chunks(data, 8, len(data))]
    assert types[0] == _RES_STRING_POOL_TYPE
    assert types[1] == _RES_XML_RESOURCE_MAP_TYPE
    # Every element opened is closed.
    assert types.count(_START_ELEMENT) == types.count(_END_ELEMENT)


def test_resource_map_covers_exactly_the_attribute_names() -> None:
    data = encode_manifest(build_manifest())
    walker = _chunks(data, 8, len(data))
    _pool_type, _pool_size, pool_start = next(walker)
    string_count = struct.unpack_from("<I", data, pool_start + 8)[0]

    map_type, map_size, _start = next(walker)
    assert map_type == _RES_XML_RESOURCE_MAP_TYPE
    mapped = (map_size - 8) // 4
    assert 0 < mapped <= string_count, \
        "the resource map must describe a prefix of the string pool"


def test_element_nesting_balances() -> None:
    data = encode_manifest(build_manifest())
    depth = 0
    deepest = 0
    for chunk_type, _size, _start in _chunks(data, 8, len(data)):
        if chunk_type == _START_ELEMENT:
            depth += 1
            deepest = max(deepest, depth)
        elif chunk_type == _END_ELEMENT:
            depth -= 1
            assert depth >= 0, "an element was closed before it was opened"
    assert depth == 0
    # manifest > application > activity > intent-filter > data
    assert deepest == 5


def test_strings_survive_the_round_trip() -> None:
    """The pool is UTF-8, which is what aapt2 emits for a modern manifest."""
    data = encode_manifest(build_manifest())
    for expected in (PACKAGE, VERSION_NAME, ANDROID_NS, "MainActivity",
                     "shop.example.com", "exampleshop",
                     "android.permission.INTERNET"):
        assert expected.encode("utf-8") in data, expected


def test_the_string_pool_declares_utf8() -> None:
    """The flag and the entry layout have to agree, or a parser reads garbage."""
    from tests.fixtures.axml import _UTF8_FLAG

    data = encode_manifest(build_manifest())
    _pool_type, _size, pool_start = next(_chunks(data, 8, len(data)))
    flags = struct.unpack_from("<I", data, pool_start + 16)[0]
    assert flags & _UTF8_FLAG


def test_built_apk_is_a_valid_zip_with_the_expected_members(tmp_path: Path) -> None:
    apk = build_apk(tmp_path / "fixture.apk")
    with zipfile.ZipFile(apk) as archive:
        assert archive.testzip() is None
        names = archive.namelist()
        for expected in ("AndroidManifest.xml", "classes.dex",
                         "lib/arm64-v8a/libshop.so", "META-INF/MANIFEST.MF"):
            assert expected in names
        assert archive.read("classes.dex").startswith(b"dex\n035\x00")
        assert archive.read("lib/arm64-v8a/libshop.so").startswith(b"\x7fELF")


def test_dex_checksum_and_signature_are_correct(tmp_path: Path) -> None:
    """A tool that validates the DEX header must accept the fixture."""
    import hashlib
    import zlib

    apk = build_apk(tmp_path / "fixture.apk")
    with zipfile.ZipFile(apk) as archive:
        dex = archive.read("classes.dex")

    assert struct.unpack_from("<I", dex, 8)[0] == zlib.adler32(dex[12:]) & 0xFFFFFFFF
    assert dex[12:32] == hashlib.sha1(dex[32:]).digest()
    assert struct.unpack_from("<I", dex, 32)[0] == len(dex)     # file_size
    assert struct.unpack_from("<I", dex, 36)[0] == 0x70         # header_size
    assert struct.unpack_from("<I", dex, 40)[0] == 0x12345678   # endian tag


def test_apk_is_deterministic(tmp_path: Path) -> None:
    """Same fixture every run: a flaky fixture would make every test flaky."""
    first = build_apk(tmp_path / "a.apk").read_bytes()
    second = build_apk(tmp_path / "b.apk").read_bytes()
    assert encode_manifest(build_manifest()) == encode_manifest(build_manifest())
    # Zip entries carry a timestamp, so compare the manifest member, not the zip.
    with zipfile.ZipFile(tmp_path / "a.apk") as a, zipfile.ZipFile(tmp_path / "b.apk") as b:
        assert a.read("AndroidManifest.xml") == b.read("AndroidManifest.xml")
    assert len(first) == len(second)


# ---------------------------------------------------------------------- dex

def test_dex_tables_are_sorted_as_the_format_requires() -> None:
    """A DEX whose tables are out of order is rejected by strict readers.

    string_ids sort by the string's own bytes, type_ids by their descriptor's
    string index. Getting this wrong produces a file that some tools accept and
    others silently refuse, which is the worst kind of fixture bug.
    """
    from tests.fixtures.dex import shop_dex

    dex = shop_dex()
    string_count, string_off = struct.unpack_from("<II", dex, 56)
    type_count, type_off = struct.unpack_from("<II", dex, 64)

    def read_string(index: int) -> bytes:
        offset = struct.unpack_from("<I", dex, string_off + 4 * index)[0]
        # uleb128 length, then MUTF-8 up to a NUL. The fixture is ASCII, so a
        # single length byte always covers it.
        end = dex.index(b"\x00", offset + 1)
        return dex[offset + 1:end]

    strings = [read_string(i) for i in range(string_count)]
    assert strings == sorted(strings), "string_ids must be sorted by content"

    type_indices = [struct.unpack_from("<I", dex, type_off + 4 * i)[0]
                    for i in range(type_count)]
    assert type_indices == sorted(type_indices), "type_ids must be sorted"


def test_dex_declares_the_classes_the_manifest_names() -> None:
    """The package has to be self-consistent.

    Every component the manifest declares should be a class that is really in
    the DEX, or the fixture is describing an app that could not run.
    """
    from tests.fixtures.dex import SHOP_CLASSES

    descriptors = {c.descriptor for c in SHOP_CLASSES}
    for component in ("MainActivity", "SyncService", "BootReceiver",
                      "data/ShopProvider"):
        assert f"Lcom/example/shop/{component};" in descriptors


def test_dex_carries_the_strings_later_stages_look_for() -> None:
    """The constants exist so 1.4 and 1.7 have something true to find."""
    from tests.fixtures.dex import shop_dex

    dex = shop_dex()
    for needle in (b"https://api.shop.example.com/v1/orders",
                   b"http://legacy.shop.example.com/v1/orders",
                   b"AKIAZZ7NLQK4PRODXYZQ"):
        assert needle in dex, needle

    # AWS's own documentation key is allowlisted by every scanner worth using,
    # so a fixture built on it asserts that a secret scanner found no secrets.
    assert b"AKIAIOSFODNN7EXAMPLE" not in dex


def test_dex_carries_real_call_sites_for_the_sast_stage() -> None:
    """semgrep matches call sites, not bare strings.

    Without these the SAST stage could only ever be asserted against a package
    with no code in it, which is a green suite proving nothing. The builder
    emits a real invoke-static, so jadx recovers
    ``Cipher.getInstance("AES/ECB/PKCS5Padding")``.
    """
    from tests.fixtures.dex import shop_dex

    dex = shop_dex()
    for needle in (b"AES/ECB/PKCS5Padding", b"MD5", b"getInstance",
                   b"Ljavax/crypto/Cipher;", b"Ljava/security/MessageDigest;"):
        assert needle in dex, needle


def test_a_method_that_invokes_builds_a_longer_body() -> None:
    """The call body is seven code units against the plain body's three.

    Getting this wrong is silent: an invoke-static that omits its register-list
    unit still assembles, and jadx then reads the following opcode as the
    register operand and refuses to decompile the method.
    """
    from tests.fixtures.dex import CIPHER, Class, Method, build_dex

    plain = build_dex([Class("La/B;", "B.java", [Method("f", "x")])])
    calling = build_dex([Class("La/B;", "B.java", [
        Method("f", "x", return_type=CIPHER, invokes=(CIPHER, "getInstance"))])])
    assert len(calling) > len(plain)


def test_dex_is_deterministic() -> None:
    from tests.fixtures.dex import shop_dex

    assert shop_dex() == shop_dex()


def test_dex_rejects_an_empty_class_list() -> None:
    import pytest

    from tests.fixtures.dex import build_dex

    with pytest.raises(ValueError, match="at least one class"):
        build_dex([])


# --------------------------------------------------------------------- arsc

def test_arsc_chunk_sizes_are_self_consistent() -> None:
    """A chunk whose declared size disagrees with its content is unparseable."""
    from tests.fixtures.arsc import shop_arsc

    table = shop_arsc()
    chunk_type, header_size, size = struct.unpack_from("<HHI", table, 0)
    assert chunk_type == 0x0002, "the file starts with a ResTable chunk"
    assert header_size == 12
    assert size == len(table), "the table declares its own length"
    assert struct.unpack_from("<I", table, 8)[0] == 1, "one package"

    # Walk the two top-level children: the value pool, then the package.
    offset = header_size
    seen = []
    while offset < len(table):
        child_type, child_header, child_size = struct.unpack_from("<HHI", table, offset)
        assert child_size > 0, "a zero-length chunk would loop forever"
        assert offset + child_size <= len(table), "a child runs past the table"
        seen.append(child_type)
        offset += child_size
    assert seen == [0x0001, 0x0200], "expected a string pool then a package"


def test_arsc_resource_ids_follow_the_package_type_entry_layout() -> None:
    from tests.fixtures.arsc import (SHOP_PACKAGE, network_security_config_id,
                                     resource_id)

    first_string = SHOP_PACKAGE.resources[0]
    assert resource_id(SHOP_PACKAGE, first_string) == 0x7F010000
    # string is type 1, layout 2, xml 3, in first-seen order.
    assert network_security_config_id() == 0x7F030000


def test_arsc_carries_what_the_later_stages_read() -> None:
    """The values exist so 1.4 and 1.7 have something true to find."""
    from tests.fixtures.arsc import shop_arsc

    table = shop_arsc()
    for needle in (b"https://api.shop.example.com/v1",
                   b"http://legacy.shop.example.com/v1",
                   b"sk_live_51H8xExampleSecretKey0000",
                   b"res/xml/network_security_config.xml"):
        assert needle in table, needle


def test_arsc_rejects_an_empty_package() -> None:
    import pytest

    from tests.fixtures.arsc import Package, build_arsc

    with pytest.raises(ValueError, match="at least one resource"):
        build_arsc(Package("com.example.empty"))


def test_the_apk_ships_a_resource_table_and_the_nsc(tmp_path: Path) -> None:
    apk = build_apk(tmp_path / "fixture.apk")
    with zipfile.ZipFile(apk) as archive:
        names = archive.namelist()
    assert "resources.arsc" in names
    assert "res/xml/network_security_config.xml" in names
    assert "res/layout/activity_main.xml" in names


def test_the_manifest_references_the_nsc_by_resource_id() -> None:
    """A wrong attribute id does not produce a wrong name, it produces a
    different attribute, and the one you meant silently disappears.

    android:networkSecurityConfig is 0x01010527. 0x010104ED, one past
    usesCleartextTraffic, is lockTaskMode, which is what this shipped as until
    the id was checked against the real framework table.
    """
    from tests.fixtures.axml import ATTRIBUTE_IDS

    assert ATTRIBUTE_IDS["networkSecurityConfig"] == 0x01010527


def test_element_text_survives_encoding() -> None:
    """A network security config puts its domains in element text."""
    from tests.fixtures.apk import build_network_security_config
    from tests.fixtures.axml import encode_manifest

    blob = encode_manifest(build_network_security_config())
    assert b"legacy.shop.example.com" in blob
