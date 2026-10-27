"""A minimal Android binary-XML (AXML) encoder, for building test APKs.

themob's first analyzer parses a real ``AndroidManifest.xml``, which is not XML
text: it is Android's binary resource format. Testing that end to end needs a
genuine APK, and the options were "download one" (unpinned, and of uncertain
licence for a repo) or "generate one". This generates one: a few hundred bytes,
deterministic, committed, with no third-party binary in the tree.

Only the subset a manifest needs is implemented, string pool, resource map,
namespaces, elements, and string/int/boolean attributes. It is a *test fixture*,
not a general AXML library.

Format reference: AOSP ``ResourceTypes.h``. Every chunk is
``uint16 type, uint16 header_size, uint32 chunk_size``.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

# Chunk types
_RES_XML_TYPE = 0x0003
_RES_STRING_POOL_TYPE = 0x0001
_RES_XML_RESOURCE_MAP_TYPE = 0x0180
_RES_XML_START_NAMESPACE_TYPE = 0x0100
_RES_XML_END_NAMESPACE_TYPE = 0x0101
_RES_XML_START_ELEMENT_TYPE = 0x0102
_RES_XML_END_ELEMENT_TYPE = 0x0103
_RES_XML_CDATA_TYPE = 0x0104

# Res_value data types
_TYPE_STRING = 0x03
_TYPE_INT_DEC = 0x10
_TYPE_INT_BOOLEAN = 0x12
_TYPE_REFERENCE = 0x01

#: ResStringPool_header flag: entries are UTF-8 rather than UTF-16LE.
_UTF8_FLAG = 0x00000100

_NO_ENTRY = 0xFFFFFFFF
ANDROID_NS = "http://schemas.android.com/apk/res/android"

# Attribute-name -> resource id, from AOSP's public attribute table. Order does
# not matter here; the encoder emits the resource map in string-pool order.
#
# These have to be *right*: a parser resolves an attribute's name from its
# resource id, so a wrong id does not produce a wrong name. It produces a
# different attribute entirely, and the one you meant silently disappears.
# (0x01010004 is manageSpaceActivity, not readPermission.)
ATTRIBUTE_IDS: dict[str, int] = {
    "label": 0x01010001,
    "name": 0x01010003,
    "permission": 0x01010006,
    "readPermission": 0x01010007,
    "writePermission": 0x01010008,
    "protectionLevel": 0x01010009,
    "debuggable": 0x0101000F,
    "exported": 0x01010010,
    "authorities": 0x01010018,
    "scheme": 0x01010027,
    "host": 0x01010028,
    "path": 0x0101002A,
    "pathPrefix": 0x0101002B,
    "minSdkVersion": 0x0101020C,
    "versionCode": 0x0101021B,
    "versionName": 0x0101021C,
    "targetSdkVersion": 0x01010270,
    "allowBackup": 0x01010280,
    "usesCleartextTraffic": 0x010104EC,
    "networkSecurityConfig": 0x01010527,
    "autoVerify": 0x010104EE,
}


@dataclass
class Attribute:
    """One attribute on an element. ``ns`` is None for un-namespaced ones."""
    name: str
    value: object
    ns: str | None = ANDROID_NS


@dataclass(frozen=True)
class Reference:
    """A resource reference, ``@type/name``, carried as its numeric id.

    Distinct from a plain int so the encoder can tell "the value 2130903040"
    from "a pointer to resource 0x7f030000".
    """
    resource_id: int


@dataclass
class Element:
    """An XML element: name, attributes, children, and optional text."""
    name: str
    attributes: list[Attribute] = field(default_factory=list)
    children: list["Element"] = field(default_factory=list)
    text: str | None = None

    def add(self, child: "Element") -> "Element":
        self.children.append(child)
        return child


class _StringPool:
    """Interning pool. Attribute names come first so the resource map aligns."""

    def __init__(self) -> None:
        self._strings: list[str] = []
        self._index: dict[str, int] = {}
        self._resource_ids: list[int] = []
        self._sealed = False

    def add_attribute_name(self, name: str) -> int:
        """Reserve an index in the resource-mapped prefix of the pool.

        Idempotent, so the encoding pass can re-request a name the collection
        pass already interned; only a *new* name after sealing is an error,
        because it would land outside the region the resource map describes.
        """
        if name in self._index:
            return self._index[name]
        if self._sealed:
            raise RuntimeError("attribute names must be added before other strings")
        index = len(self._strings)
        self._strings.append(name)
        self._index[name] = index
        self._resource_ids.append(ATTRIBUTE_IDS.get(name, 0))
        return index

    def add(self, value: str) -> int:
        self._sealed = True
        if value in self._index:
            return self._index[value]
        index = len(self._strings)
        self._strings.append(value)
        self._index[value] = index
        return index

    @property
    def resource_ids(self) -> list[int]:
        return list(self._resource_ids)

    def encode(self, utf8: bool = True) -> bytes:
        return encode_string_pool(self._strings, utf8=utf8)


def encode_string_pool(strings: list[str], utf8: bool = True) -> bytes:
    """Encode a ResStringPool chunk.

    Shared with :mod:`tests.fixtures.arsc`, which needs three of these: the
    table's value pool and the package's type and key pools. One implementation,
    so a format mistake cannot be right in one file and wrong in another.

    UTF-8 by default, which is what aapt2 emits for a modern package. Each UTF-8
    entry is ``u8 char_count, u8 byte_count, bytes, NUL``; the UTF-16 form is
    ``u16 char_count, UTF-16LE, NUL NUL``. Both are in the format, but tooling
    is exercised far harder against UTF-8.
    """
    offsets: list[int] = []
    data = bytearray()
    for text in strings:
        offsets.append(len(data))
        if utf8:
            encoded = text.encode("utf-8")
            if len(text) > 0x7F or len(encoded) > 0x7F:
                raise ValueError(
                    "fixture strings stay short: the two-byte length form "
                    f"is not implemented ({text[:40]!r})")
            data += bytes((len(text), len(encoded))) + encoded + b"\x00"
        else:
            data += (struct.pack("<H", len(text))
                     + text.encode("utf-16-le") + b"\x00\x00")
    while len(data) % 4:                       # chunks are 4-byte aligned
        data += b"\x00"

    header_size = 28
    strings_start = header_size + 4 * len(offsets)
    chunk_size = strings_start + len(data)
    header = struct.pack(
        "<HHIIIIII",
        _RES_STRING_POOL_TYPE, header_size, chunk_size,
        len(strings), 0,                       # string count, style count
        _UTF8_FLAG if utf8 else 0,
        strings_start, 0,                      # strings start, styles start
    )
    return header + b"".join(struct.pack("<I", o) for o in offsets) + bytes(data)


class AxmlEncoder:
    """Encodes an :class:`Element` tree into AXML bytes."""

    def __init__(self) -> None:
        self._pool = _StringPool()
        self._body = bytearray()

    def encode(self, root: Element) -> bytes:
        # Pass 1: intern every attribute name, so they occupy the pool prefix
        # the resource map describes.
        self._collect_attribute_names(root)
        # Pass 2: intern everything else and build the chunk body.
        ns_prefix = self._pool.add("android")
        ns_uri = self._pool.add(ANDROID_NS)

        self._chunk(_RES_XML_START_NAMESPACE_TYPE, 16,
                    struct.pack("<IIII", 1, _NO_ENTRY, ns_prefix, ns_uri))
        self._element(root, ns_uri)
        self._chunk(_RES_XML_END_NAMESPACE_TYPE, 16,
                    struct.pack("<IIII", 1, _NO_ENTRY, ns_prefix, ns_uri))

        pool = self._pool.encode()
        resource_map = self._resource_map()
        payload = pool + resource_map + bytes(self._body)
        header = struct.pack("<HHI", _RES_XML_TYPE, 8, 8 + len(payload))
        return header + payload

    # -- passes ---------------------------------------------------------------

    def _collect_attribute_names(self, element: Element) -> None:
        for attribute in element.attributes:
            self._pool.add_attribute_name(attribute.name)
        for child in element.children:
            self._collect_attribute_names(child)

    def _resource_map(self) -> bytes:
        ids = self._pool.resource_ids
        body = b"".join(struct.pack("<I", value) for value in ids)
        return struct.pack("<HHI", _RES_XML_RESOURCE_MAP_TYPE, 8,
                           8 + len(body)) + body

    def _element(self, element: Element, ns_uri: int) -> None:
        name_index = self._pool.add(element.name)
        attributes = b"".join(self._attribute(a, ns_uri)
                              for a in element.attributes)
        body = struct.pack(
            "<IIIIHHHHHH",
            1, _NO_ENTRY,                          # line number, comment
            _NO_ENTRY, name_index,                 # namespace, name
            20, 20, len(element.attributes),       # attr start, size, count
            0, 0, 0,                               # id, class, style index
        ) + attributes
        self._chunk(_RES_XML_START_ELEMENT_TYPE, 16, body)

        # A network security config puts its domains in element text, so text
        # nodes are not optional for this fixture.
        if element.text is not None:
            text_index = self._pool.add(element.text)
            self._chunk(_RES_XML_CDATA_TYPE, 16, struct.pack(
                "<IIIHBBI",
                1, _NO_ENTRY,                      # line number, comment
                text_index,                        # the text itself
                8, 0, _TYPE_STRING, text_index))   # typed value

        for child in element.children:
            self._element(child, ns_uri)

        self._chunk(_RES_XML_END_ELEMENT_TYPE, 16,
                    struct.pack("<IIII", 1, _NO_ENTRY, _NO_ENTRY, name_index))

    def _attribute(self, attribute: Attribute, ns_uri: int) -> bytes:
        ns = ns_uri if attribute.ns else _NO_ENTRY
        # Interned during the collection pass, so this is always a lookup.
        name = self._pool.add_attribute_name(attribute.name)
        value = attribute.value

        if isinstance(value, Reference):
            raw, data_type, data = _NO_ENTRY, _TYPE_REFERENCE, value.resource_id
        elif isinstance(value, bool):
            raw, data_type, data = _NO_ENTRY, _TYPE_INT_BOOLEAN, (
                0xFFFFFFFF if value else 0)
        elif isinstance(value, int):
            raw, data_type, data = _NO_ENTRY, _TYPE_INT_DEC, value & 0xFFFFFFFF
        else:
            index = self._pool.add(str(value))
            raw, data_type, data = index, _TYPE_STRING, index

        return struct.pack("<IIIHBBI", ns, name, raw, 8, 0, data_type, data)

    def _chunk(self, chunk_type: int, header_size: int, body: bytes) -> None:
        self._body += struct.pack("<HHI", chunk_type, header_size,
                                  8 + len(body)) + body


def encode_manifest(root: Element) -> bytes:
    """Encode a manifest element tree into AndroidManifest.xml bytes."""
    return AxmlEncoder().encode(root)
