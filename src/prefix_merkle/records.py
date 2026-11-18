"""Bounded flat-record encoding and strict JSON wire artifacts.

This application encoding is deliberately not RFC 8785 / general canonical JSON.
"""

import json
import re

from .tree import MAX_LEAF_BYTES, MAX_LEAVES, MAX_TOTAL_BYTES, MerkleTree, TreeHead

FORMAT = "prefix-merkle-sha256-v1"
ENCODING = "flat-json-v1"


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _no_constant(value):
    raise ValueError("non-finite JSON number")


def parse_json(raw):
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    return json.loads(raw, object_pairs_hook=_unique, parse_constant=_no_constant)


def encode_record(record):
    if type(record) is not dict or not 1 <= len(record) <= 32:
        raise ValueError("a record needs 1..32 fields")
    for key, value in record.items():
        if type(key) is not str or re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]{0,63}", key) is None:
            raise ValueError("field names must be bounded ASCII identifiers")
        if value is None or type(value) is bool:
            continue
        if type(value) is int:
            if not -(1 << 63) <= value < 1 << 63:
                raise ValueError("integer fields must fit signed int64")
        elif type(value) is str:
            try:
                if len(value.encode("utf-8")) > 4096:
                    raise ValueError("string fields are limited to 4096 UTF-8 bytes")
            except UnicodeEncodeError as error:
                raise ValueError("unpaired Unicode surrogate") from error
        else:
            raise ValueError("only null, boolean, int64, and string fields are supported")
    encoded = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if len(encoded) > MAX_LEAF_BYTES:
        raise ValueError("encoded record exceeds 16 KiB")
    return encoded


def read_json(path, limit=16384):
    with open(path, "rb") as handle:
        raw = handle.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("JSON document exceeds its byte limit")
    return parse_json(raw)


def read_dataset(path):
    leaves, total = [], 0
    with open(path, "rb") as handle:
        while True:
            line = handle.readline(MAX_LEAF_BYTES + 2)
            if not line:
                break
            total += len(line)
            if len(line) > MAX_LEAF_BYTES + 1 or total > MAX_TOTAL_BYTES or len(leaves) >= MAX_LEAVES:
                raise ValueError("JSONL exceeds line, total-byte, or row limit")
            if not line.strip():
                raise ValueError("blank JSONL records are not accepted")
            leaves.append(encode_record(parse_json(line)))
    return MerkleTree(leaves)


def head_document(head):
    return {"format": FORMAT, "encoding": ENCODING, "size": head.size, "root": head.root.hex()}


def _fields(doc, expected):
    if type(doc) is not dict or set(doc) != set(expected):
        raise ValueError("unexpected or missing document fields")
    if doc["format"] != FORMAT or doc["encoding"] != ENCODING:
        raise ValueError("unsupported format or record encoding")


def _hex(value):
    if type(value) is not str or re.fullmatch("[0-9a-f]{64}", value) is None:
        raise ValueError("digest must be 64 lowercase hexadecimal characters")
    return bytes.fromhex(value)


def parse_head(doc):
    _fields(doc, ("format", "encoding", "size", "root"))
    return TreeHead(doc["size"], _hex(doc["root"]))


def proof_document(tree, kind, position):
    base = {"format": FORMAT, "encoding": ENCODING, "kind": kind, "size": tree.head.size}
    if kind == "inclusion":
        base.update(index=position, siblings=[x.hex() for x in tree.inclusion(position)])
    elif kind == "consistency":
        base.update(old_size=position, siblings=[x.hex() for x in tree.consistency(position)])
    else:
        raise ValueError("unknown proof kind")
    return base


def parse_proof(doc, kind):
    if kind not in ("inclusion", "consistency"):
        raise ValueError("unknown proof kind")
    position = "index" if kind == "inclusion" else "old_size"
    _fields(doc, ("format", "encoding", "kind", "size", position, "siblings"))
    if doc["kind"] != kind or type(doc["siblings"]) is not list or len(doc["siblings"]) > 13:
        raise ValueError("invalid proof kind or sibling list")
    if type(doc["size"]) is not int or not 0 <= doc["size"] <= MAX_LEAVES:
        raise ValueError("invalid proof size")
    value = doc[position]
    upper = doc["size"] - 1 if kind == "inclusion" else doc["size"]
    if type(value) is not int or not 0 <= value <= upper:
        raise ValueError("invalid proof index or prefix size")
    return doc["size"], value, tuple(_hex(node) for node in doc["siblings"])
