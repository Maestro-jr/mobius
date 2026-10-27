"""Builds a real, decompilable ``classes.dex``.

The fixture used to ship a DEX header with nothing behind it. That was enough
for androguard to inventory the file, but a decompiler underflows on it, so
jadx could never produce Java and four of its end-to-end tests had to skip.

This emits a genuine DEX (format 035): string, type, proto and method tables, a
class_def per class, real bytecode in a code_item, and a map_list. jadx reads it
and writes Java, so the reverse-engineering stage can be asserted rather than
skipped.

Only the subset a small class needs is implemented: static methods that either
return a constant or make one static call with a string literal. No fields, no
interfaces, no annotations, no try/catch, no debug info. Enough to be real,
small enough to stay readable.

The contents are chosen so later stages have something true to find: an HTTPS
endpoint for the endpoint extractor (1.7), secret-shaped strings for gitleaks
and apkleaks (1.4), and real call sites for semgrep (1.5). That last one is why
``invokes`` exists at all. A SAST tool matches calls, so a fixture holding only
bare strings lets the suite go green while asserting that a code scanner found
no code.

Still out of reach: anything needing more than one register or a StringBuilder,
which rules out string concatenation and therefore the classic injection
patterns. Those want a real invoke sequence with locals, and that is the next
thing to add here if the SAST rules need it.

Reference: the Dalvik executable format, ordering rules included. The tables are
sorted because the format requires it, not for tidiness: a DEX whose string_ids
are out of order is rejected by strict readers.
"""
from __future__ import annotations

import hashlib
import struct
import zlib
from dataclasses import dataclass, field

HEADER_SIZE = 0x70
ENDIAN_TAG = 0x12345678

# Map item type codes, from the format specification.
TYPE_HEADER_ITEM = 0x0000
TYPE_STRING_ID_ITEM = 0x0001
TYPE_TYPE_ID_ITEM = 0x0002
TYPE_PROTO_ID_ITEM = 0x0003
TYPE_METHOD_ID_ITEM = 0x0005
TYPE_CLASS_DEF_ITEM = 0x0006
TYPE_MAP_LIST = 0x1000
TYPE_TYPE_LIST = 0x1001
TYPE_CODE_ITEM = 0x2001
TYPE_STRING_DATA_ITEM = 0x2002
TYPE_CLASS_DATA_ITEM = 0x2000

ACC_PUBLIC = 0x0001
ACC_STATIC = 0x0008

OBJECT = "Ljava/lang/Object;"
STRING = "Ljava/lang/String;"
CIPHER = "Ljavax/crypto/Cipher;"
MESSAGE_DIGEST = "Ljava/security/MessageDigest;"


@dataclass(frozen=True)
class Method:
    """A static method.

    By default the whole body is ``return "constant";``, which is enough for
    anything that reads strings: the endpoint extractor and the secret scanners
    both work off string constants.

    With ``invokes`` set to ``(owner, callee)`` the body becomes
    ``return Owner.callee("constant");`` instead. That exists for the SAST
    stage: semgrep matches *call sites*, and a fixture that only holds bare
    strings can never exercise it, so the suite would go green while asserting
    that a code scanner found no code.
    """

    name: str
    constant: str
    return_type: str = STRING
    invokes: tuple[str, str] | None = None      # (owner descriptor, callee name)


@dataclass
class Class:
    descriptor: str                         # e.g. "Lcom/example/shop/Api;"
    source_file: str
    methods: list[Method] = field(default_factory=list)
    superclass: str = OBJECT


def _uleb128(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _mutf8(text: str) -> bytes:
    """Modified UTF-8. For the ASCII this fixture uses it is plain UTF-8."""
    return text.encode("utf-8")


def _align(blob: bytearray, boundary: int) -> None:
    while len(blob) % boundary:
        blob.append(0)


def _shorty(return_type: str) -> str:
    """The shorty descriptor for a no-argument method."""
    return "L" if return_type.startswith(("L", "[")) else return_type


def build_dex(classes: list[Class]) -> bytes:
    """Assemble a DEX file containing *classes*."""
    if not classes:
        raise ValueError("a DEX needs at least one class")

    # -- 1. every string the file references ---------------------------------
    strings: set[str] = {OBJECT, STRING}
    for cls in classes:
        strings.update({cls.descriptor, cls.superclass, cls.source_file})
        for method in cls.methods:
            strings.update({method.name, method.constant, method.return_type,
                            _shorty(method.return_type)})
            if method.invokes:
                owner, callee = method.invokes
                # The callee takes one String and returns what the caller
                # returns, so its shorty is the return shorty plus one 'L'.
                strings.update({owner, callee,
                                _shorty(method.return_type) + "L"})
    # The format requires string_ids sorted by the string's own bytes.
    string_list = sorted(strings, key=_mutf8)
    string_index = {s: i for i, s in enumerate(string_list)}

    # -- 2. types, sorted by descriptor string index --------------------------
    type_set = {cls.descriptor for cls in classes}
    type_set.update(cls.superclass for cls in classes)
    type_set.update(m.return_type for cls in classes for m in cls.methods)
    for cls in classes:
        for m in cls.methods:
            if m.invokes:
                # The callee's owner, and String for its parameter list.
                type_set.update({m.invokes[0], STRING})
    type_list = sorted(type_set, key=lambda d: string_index[d])
    type_index = {d: i for i, d in enumerate(type_list)}

    # -- 3. prototypes, sorted by return type then parameters -----------------
    # A proto is (shorty, return type, parameter types). Everything themob's
    # fixture defines takes no arguments; the one-String proto exists for the
    # external methods a body invokes.
    proto_set: set[tuple[str, str, tuple[str, ...]]] = set()
    for cls in classes:
        for m in cls.methods:
            proto_set.add((_shorty(m.return_type), m.return_type, ()))
            if m.invokes:
                proto_set.add((_shorty(m.return_type) + "L", m.return_type,
                               (STRING,)))
    proto_list = sorted(
        proto_set,
        key=lambda p: (type_index[p[1]], tuple(type_index[t] for t in p[2])))
    proto_index = {p: i for i, p in enumerate(proto_list)}

    # -- 4. methods, sorted by class, then name, then prototype ---------------
    # Both the methods these classes define and the external ones their bodies
    # call: a DEX references a callee through the same method_ids table.
    method_set = set()
    for cls in classes:
        for m in cls.methods:
            method_set.add((cls.descriptor, m.name,
                            (_shorty(m.return_type), m.return_type, ())))
            if m.invokes:
                owner, callee = m.invokes
                method_set.add((owner, callee,
                                (_shorty(m.return_type) + "L", m.return_type,
                                 (STRING,))))
    method_list = sorted(
        method_set,
        key=lambda t: (type_index[t[0]], string_index[t[1]], proto_index[t[2]]))
    method_index = {m: i for i, m in enumerate(method_list)}

    # -- 5. lay out the data section -----------------------------------------
    # Offsets are absolute, so the fixed-size tables have to be measured first.
    string_ids_off = HEADER_SIZE
    type_ids_off = string_ids_off + 4 * len(string_list)
    proto_ids_off = type_ids_off + 4 * len(type_list)
    method_ids_off = proto_ids_off + 12 * len(proto_list)
    class_defs_off = method_ids_off + 8 * len(method_list)
    data_off = class_defs_off + 32 * len(classes)

    data = bytearray()

    def here() -> int:
        return data_off + len(data)

    # type_list items first, because a parameterised proto points at one and the
    # map list has to stay sorted by offset.
    _align(data, 4)
    type_list_off: dict[tuple[str, ...], int] = {}
    parameter_lists = sorted({p[2] for p in proto_list if p[2]},
                             key=lambda ts: tuple(type_index[t] for t in ts))
    type_list_start = here()
    for parameters in parameter_lists:
        _align(data, 4)
        type_list_off[parameters] = here()
        data += struct.pack("<I", len(parameters))
        for descriptor in parameters:
            data += struct.pack("<H", type_index[descriptor])

    string_data_off: dict[str, int] = {}
    string_data_start = here()
    for text in string_list:
        string_data_off[text] = here()
        encoded = _mutf8(text)
        data += _uleb128(len(text))          # utf16 units, ASCII so len() works
        data += encoded + b"\x00"

    # code_items must be 4-byte aligned.
    _align(data, 4)
    code_start = here()
    code_off: dict[tuple[str, str], int] = {}
    code_count = 0
    for cls in classes:
        for method in cls.methods:
            _align(data, 4)
            code_off[(cls.descriptor, method.name)] = here()
            code_count += 1
            if method.invokes:
                owner, callee = method.invokes
                callee_idx = method_index[(
                    owner, callee,
                    (_shorty(method.return_type) + "L", method.return_type,
                     (STRING,)))]
                # const-string v0, <constant>       (0x1a, format 21c, 2 units)
                # invoke-static {v0}, callee@BBBB   (0x71, format 35c, 3 units)
                #   unit 0: high byte is (argument count << 4) | 5th register,
                #           so one argument is 0x10, giving 0x1071
                #   unit 1: the method index
                #   unit 2: the register list, F|E|D|C, so v0 is 0x0000.
                #           Omitting this third unit is not a short encoding,
                #           it silently shifts everything after it: jadx then
                #           read the next opcode as the register operand and
                #           reported a call on r12.
                # move-result-object v0             (0x0c, format 11x, 1 unit)
                # return-object v0                  (0x11, format 11x, 1 unit)
                insns = struct.pack("<HHHHHHH",
                                    0x001A, string_index[method.constant],
                                    0x1071, callee_idx, 0x0000,
                                    0x000C, 0x0011)
                outs = 1
            else:
                # const-string v0, <constant>   (opcode 0x1a, format 21c)
                # return-object v0              (opcode 0x11, format 11x)
                insns = struct.pack("<HHH", 0x001A,
                                    string_index[method.constant], 0x0011)
                outs = 0
            data += struct.pack("<HHHHII",
                                1,            # registers_size
                                0,            # ins_size
                                outs,         # outs_size
                                0,            # tries_size
                                0,            # debug_info_off
                                len(insns) // 2)
            data += insns

    class_data_start = here()
    class_data_off: dict[str, int] = {}
    for cls in classes:
        class_data_off[cls.descriptor] = here()
        data += _uleb128(0)                   # static_fields_size
        data += _uleb128(0)                   # instance_fields_size
        data += _uleb128(len(cls.methods))    # direct_methods_size
        data += _uleb128(0)                   # virtual_methods_size
        previous = 0
        # encoded_method indices are stored as deltas, so they must ascend.
        ordered = sorted(cls.methods,
                         key=lambda m: method_index[(cls.descriptor, m.name,
                                                     (_shorty(m.return_type),
                                                      m.return_type, ()))])
        for method in ordered:
            idx = method_index[(cls.descriptor, method.name,
                                (_shorty(method.return_type),
                                 method.return_type, ()))]
            data += _uleb128(idx - previous)
            previous = idx
            data += _uleb128(ACC_PUBLIC | ACC_STATIC)
            data += _uleb128(code_off[(cls.descriptor, method.name)])

    # -- 6. the map list, last, 4-byte aligned --------------------------------
    _align(data, 4)
    map_off = here()
    entries = [
        (TYPE_HEADER_ITEM, 1, 0),
        (TYPE_STRING_ID_ITEM, len(string_list), string_ids_off),
        (TYPE_TYPE_ID_ITEM, len(type_list), type_ids_off),
        (TYPE_PROTO_ID_ITEM, len(proto_list), proto_ids_off),
        (TYPE_METHOD_ID_ITEM, len(method_list), method_ids_off),
        (TYPE_CLASS_DEF_ITEM, len(classes), class_defs_off),
    ]
    if parameter_lists:
        entries.append((TYPE_TYPE_LIST, len(parameter_lists), type_list_start))
    entries += [
        (TYPE_STRING_DATA_ITEM, len(string_list), string_data_start),
        (TYPE_CODE_ITEM, code_count, code_start),
        (TYPE_CLASS_DATA_ITEM, len(classes), class_data_start),
        (TYPE_MAP_LIST, 1, map_off),
    ]
    data += struct.pack("<I", len(entries))
    for type_code, size, offset in entries:
        data += struct.pack("<HHII", type_code, 0, size, offset)

    # -- 7. the fixed tables --------------------------------------------------
    string_ids = b"".join(struct.pack("<I", string_data_off[s])
                          for s in string_list)
    type_ids = b"".join(struct.pack("<I", string_index[d]) for d in type_list)
    proto_ids = b"".join(
        struct.pack("<III", string_index[shorty], type_index[ret],
                    type_list_off[params] if params else 0)
        for shorty, ret, params in proto_list)
    method_ids = b"".join(
        struct.pack("<HHI", type_index[owner], proto_index[proto],
                    string_index[name])
        for owner, name, proto in method_list)
    class_defs = b"".join(
        struct.pack("<IIIIIIII",
                    type_index[cls.descriptor],
                    ACC_PUBLIC,
                    type_index[cls.superclass],
                    0,                                    # interfaces_off
                    string_index[cls.source_file],
                    0,                                    # annotations_off
                    class_data_off[cls.descriptor],
                    0)                                    # static_values_off
        for cls in classes)

    file_size = data_off + len(data)

    header = bytearray(b"dex\n035\x00")
    header += b"\x00" * 4                                 # checksum, later
    header += b"\x00" * 20                                # signature, later
    header += struct.pack("<I", file_size)
    header += struct.pack("<I", HEADER_SIZE)
    header += struct.pack("<I", ENDIAN_TAG)
    header += struct.pack("<II", 0, 0)                    # link_size, link_off
    header += struct.pack("<I", map_off)
    header += struct.pack("<II", len(string_list), string_ids_off)
    header += struct.pack("<II", len(type_list), type_ids_off)
    header += struct.pack("<II", len(proto_list), proto_ids_off)
    header += struct.pack("<II", 0, 0)                    # field_ids
    header += struct.pack("<II", len(method_list), method_ids_off)
    header += struct.pack("<II", len(classes), class_defs_off)
    header += struct.pack("<II", file_size - data_off, data_off)
    if len(header) != HEADER_SIZE:
        raise AssertionError(f"header is {len(header)} bytes, expected {HEADER_SIZE}")

    blob = bytearray(header) + string_ids + type_ids + proto_ids
    blob += method_ids + class_defs + data
    if len(blob) != file_size:
        raise AssertionError(f"file is {len(blob)} bytes, header says {file_size}")

    # The signature covers everything after it; the checksum covers everything
    # after itself, signature included, so they must be written in this order.
    blob[12:32] = hashlib.sha1(bytes(blob[32:])).digest()
    blob[8:12] = struct.pack("<I", zlib.adler32(bytes(blob[12:])) & 0xFFFFFFFF)
    return bytes(blob)


# The classes the fixture manifest declares, so the package is self-consistent:
# every component android:name points at a class that is really in the DEX.
SHOP_CLASSES = [
    Class("Lcom/example/shop/MainActivity;", "MainActivity.java", [
        Method("endpoint", "https://api.shop.example.com/v1/orders"),
        Method("fallbackEndpoint", "http://legacy.shop.example.com/v1/orders"),
    ]),
    Class("Lcom/example/shop/SyncService;", "SyncService.java", [
        # Secret-shaped, and fake. apkleaks and gitleaks (1.4) find these.
        #
        # Not AWS's own AKIAIOSFODNN7EXAMPLE, which every scanner allowlists
        # precisely because it appears in the documentation. A fixture built
        # from it tests nothing: gitleaks skips it and the suite passes while
        # asserting that a secret scanner found no secrets.
        Method("apiKey", "AKIAZZ7NLQK4PRODXYZQ"),
        Method("bucket", "https://shop-example-uploads.s3.amazonaws.com"),
        # Two call sites for the SAST stage (1.5). Both are textbook crypto
        # misuse and both are a single static call with a string literal, which
        # is the shape this builder can express: ECB leaks plaintext structure,
        # and MD5 has been unfit for anything security-relevant for years.
        Method("cipher", "AES/ECB/PKCS5Padding",
               return_type=CIPHER, invokes=(CIPHER, "getInstance")),
        Method("digest", "MD5",
               return_type=MESSAGE_DIGEST, invokes=(MESSAGE_DIGEST, "getInstance")),
    ]),
    Class("Lcom/example/shop/BootReceiver;", "BootReceiver.java", [
        Method("action", "android.intent.action.BOOT_COMPLETED"),
    ]),
    Class("Lcom/example/shop/data/ShopProvider;", "ShopProvider.java", [
        Method("authority", "com.example.shop.provider"),
    ]),
]


def shop_dex() -> bytes:
    """The DEX that goes with the fixture manifest."""
    return build_dex(SHOP_CLASSES)
