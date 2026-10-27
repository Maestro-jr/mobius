"""Builds a minimal but valid ``resources.arsc``.

Without a resource table apktool decodes with framework resources only and
emits no ``res/`` tree at all, so the stages that read resources have nothing to
read: the secret scanners (1.4) and the endpoint extractor (1.7) scan an empty
directory, and the config auditor's network-security-config checks never run end
to end because no NSC file is ever resolved.

This emits a real table: a value string pool, one package, its type and key
pools, and a typeSpec plus type chunk per resource type. Only the subset a small
package needs is implemented. Every entry is a simple (non-bag) entry holding a
string value, in the default configuration. No configuration variants, no
styles, no bags, no public.xml.

Layout of the file, all little-endian, every chunk 4-byte aligned::

    ResTable            (0x0002)  packageCount
      ResStringPool     (0x0001)  the values every entry points at
      ResTable_package  (0x0200)  id 0x7f, the app's own package
        ResStringPool   (0x0001)  type names: string, layout, xml
        ResStringPool   (0x0001)  key names: the entry names
        ResTable_typeSpec (0x0202) + ResTable_type (0x0201), once per type

A resource id is ``0xPPTTEEEE``: package, type (1-based), entry.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

from .axml import encode_string_pool

RES_TABLE_TYPE = 0x0002
RES_TABLE_PACKAGE_TYPE = 0x0200
RES_TABLE_TYPE_TYPE = 0x0201
RES_TABLE_TYPE_SPEC_TYPE = 0x0202

TYPE_STRING = 0x03                      # Res_value data is a string-pool index

PACKAGE_ID = 0x7F                       # the id every app package uses
NO_ENTRY = 0xFFFFFFFF

# A ResTable_config whose first field is its own size. All zero after that is
# the default configuration, which is the only one this fixture needs.
_CONFIG_SIZE = 56
_CONFIG = struct.pack("<I", _CONFIG_SIZE) + bytes(_CONFIG_SIZE - 4)

_PACKAGE_HEADER_SIZE = 288              # 8 + 4 + 256 + 4 + 4 + 4 + 4 + 4
_TYPE_HEADER_SIZE = 20 + _CONFIG_SIZE
_TYPE_SPEC_HEADER_SIZE = 16


@dataclass(frozen=True)
class Resource:
    """One entry: ``@<type>/<name>`` resolving to a string value.

    For a file-backed type such as ``layout`` or ``xml`` the value is the path
    of the file inside the archive, which is how a real package points at one.
    """

    type: str
    name: str
    value: str


@dataclass
class Package:
    name: str
    resources: list[Resource] = field(default_factory=list)
    id: int = PACKAGE_ID


def _chunk(chunk_type: int, header_size: int, header_rest: bytes,
           body: bytes = b"") -> bytes:
    size = 8 + len(header_rest) + len(body)
    if 8 + len(header_rest) != header_size:
        raise AssertionError(
            f"chunk 0x{chunk_type:04x} header is {8 + len(header_rest)} bytes, "
            f"declared {header_size}")
    return struct.pack("<HHI", chunk_type, header_size, size) + header_rest + body


def _package_name(name: str) -> bytes:
    """128 UTF-16 code units, NUL padded. Longer names are truncated by aapt."""
    if len(name) > 127:
        raise ValueError("package name does not fit in the 128-unit field")
    return name.encode("utf-16-le").ljust(256, b"\x00")


def build_arsc(package: Package) -> bytes:
    """Assemble a resource table for *package*."""
    if not package.resources:
        raise ValueError("a resource table needs at least one resource")

    # -- 1. group by type, preserving first-seen order so ids stay stable -----
    type_names: list[str] = []
    by_type: dict[str, list[Resource]] = {}
    for resource in package.resources:
        if resource.type not in by_type:
            type_names.append(resource.type)
            by_type[resource.type] = []
        by_type[resource.type].append(resource)

    # -- 2. the three string pools -------------------------------------------
    # Values are shared across the whole table; keys and type names belong to
    # the package.
    values: list[str] = []
    value_index: dict[str, int] = {}
    for resource in package.resources:
        if resource.value not in value_index:
            value_index[resource.value] = len(values)
            values.append(resource.value)

    keys: list[str] = []
    key_index: dict[str, int] = {}
    for resource in package.resources:
        if resource.name not in key_index:
            key_index[resource.name] = len(keys)
            keys.append(resource.name)

    value_pool = encode_string_pool(values)
    type_pool = encode_string_pool(type_names)
    key_pool = encode_string_pool(keys)

    # -- 3. one typeSpec + type chunk per type -------------------------------
    type_chunks = bytearray()
    for type_id, type_name in enumerate(type_names, start=1):
        entries = by_type[type_name]
        count = len(entries)

        # Every entry is in the default configuration only, so no config flags.
        spec = _chunk(
            RES_TABLE_TYPE_SPEC_TYPE, _TYPE_SPEC_HEADER_SIZE,
            struct.pack("<BBHI", type_id, 0, 0, count),
            b"".join(struct.pack("<I", 0) for _ in range(count)))

        offsets = bytearray()
        payload = bytearray()
        for resource in entries:
            offsets += struct.pack("<I", len(payload))
            # ResTable_entry: size, flags (0 = simple), key index.
            payload += struct.pack("<HHI", 8, 0, key_index[resource.name])
            # Res_value: size, res0, dataType, data.
            payload += struct.pack("<HBBI", 8, 0, TYPE_STRING,
                                   value_index[resource.value])

        entries_start = _TYPE_HEADER_SIZE + len(offsets)
        table = _chunk(
            RES_TABLE_TYPE_TYPE, _TYPE_HEADER_SIZE,
            struct.pack("<BBHII", type_id, 0, 0, count, entries_start) + _CONFIG,
            bytes(offsets) + bytes(payload))

        type_chunks += spec + table

    # -- 4. the package chunk -------------------------------------------------
    # typeStrings and keyStrings are offsets from the start of this chunk.
    type_strings_off = _PACKAGE_HEADER_SIZE
    key_strings_off = type_strings_off + len(type_pool)
    package_header = (
        struct.pack("<I", package.id)
        + _package_name(package.name)
        + struct.pack("<IIIII",
                      type_strings_off, len(type_names),
                      key_strings_off, len(keys),
                      0))                                   # typeIdOffset
    package_chunk = _chunk(
        RES_TABLE_PACKAGE_TYPE, _PACKAGE_HEADER_SIZE, package_header,
        type_pool + key_pool + bytes(type_chunks))

    # -- 5. the table ---------------------------------------------------------
    return _chunk(RES_TABLE_TYPE, 12, struct.pack("<I", 1),
                  value_pool + package_chunk)


def resource_id(package: Package, resource: Resource) -> int:
    """The ``0xPPTTEEEE`` id a manifest reference has to carry."""
    type_names: list[str] = []
    by_type: dict[str, list[Resource]] = {}
    for item in package.resources:
        if item.type not in by_type:
            type_names.append(item.type)
            by_type[item.type] = []
        by_type[item.type].append(item)

    type_id = type_names.index(resource.type) + 1
    entry_id = by_type[resource.type].index(resource)
    return (package.id << 24) | (type_id << 16) | entry_id


# The resources the fixture package declares. Values are chosen for the stages
# that read them: a cleartext endpoint and an HTTPS one for the endpoint
# extractor (1.7), and a secret-shaped string for gitleaks and apkleaks (1.4).
NETWORK_SECURITY_CONFIG = Resource(
    "xml", "network_security_config", "res/xml/network_security_config.xml")

SHOP_RESOURCES = [
    Resource("string", "app_name", "Example Shop"),
    Resource("string", "api_base", "https://api.shop.example.com/v1"),
    Resource("string", "legacy_api", "http://legacy.shop.example.com/v1"),
    Resource("string", "analytics_key", "sk_live_51H8xExampleSecretKey0000"),
    Resource("layout", "activity_main", "res/layout/activity_main.xml"),
    NETWORK_SECURITY_CONFIG,
]

SHOP_PACKAGE = Package("com.example.shop", SHOP_RESOURCES)


def shop_arsc() -> bytes:
    """The resource table that goes with the fixture manifest."""
    return build_arsc(SHOP_PACKAGE)


def network_security_config_id() -> int:
    """The id ``android:networkSecurityConfig`` points at."""
    return resource_id(SHOP_PACKAGE, NETWORK_SECURITY_CONFIG)
