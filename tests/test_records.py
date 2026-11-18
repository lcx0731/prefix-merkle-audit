import pytest

from prefix_merkle import MerkleTree, encode_record
from prefix_merkle.records import head_document, parse_head, parse_json, parse_proof, proof_document, read_dataset


def test_encoding_has_a_published_byte_contract():
    record = {"text": "é\n", "flag": True, "count": -4, "missing": None}
    assert encode_record(record) == b'{"count":-4,"flag":true,"missing":null,"text":"\xc3\xa9\\n"}'
    assert encode_record(parse_json(b'{ "count": -4, "missing":null, "flag": true, "text":"\\u00e9\\n" }')) == encode_record(record)
    assert encode_record({"x": True}) != encode_record({"x": 1})
    assert encode_record({"x": 1}) != encode_record({"x": "1"})
    assert encode_record({"x": "é"}) != encode_record({"x": "e\u0301"})
    for value in (-(1 << 63), (1 << 63) - 1):
        assert parse_json(encode_record({"x": value}))["x"] == value


@pytest.mark.parametrize("record", [{}, [], {"x": 1.5}, {"x": float("nan")}, {"x": []}, {"x": {}},
                                      {"x": 1 << 63}, {"x": -(1 << 63) - 1}, {"x": "a" * 4097},
                                      {"x": "\ud800"}, {"bad key": 1}, {1: "x"}, {"x" * 65: 1}])
def test_invalid_records(record):
    with pytest.raises(ValueError):
        encode_record(record)


def test_field_and_encoded_size_limits():
    with pytest.raises(ValueError):
        encode_record({f"k{i}": 0 for i in range(33)})
    with pytest.raises(ValueError):
        encode_record({f"k{i}": "x" * 4096 for i in range(4)})


@pytest.mark.parametrize("raw", [b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', '{"x":1}'.encode("utf-16")])
def test_ambiguous_or_non_utf8_source_rejected(raw):
    with pytest.raises(ValueError):
        parse_json(raw)


def test_jsonl_record_order_and_whitespace(tmp_path):
    path = tmp_path / "rows.jsonl"
    path.write_bytes(b'{"b":2,"a":1}\n { "x": true }\n')
    tree = read_dataset(path)
    assert tree.leaves == (b'{"a":1,"b":2}', b'{"x":true}')
    assert tree.head != MerkleTree(reversed(tree.leaves)).head
    path.write_bytes(b"")
    assert read_dataset(path).head.size == 0
    for raw in (b'\n', b'{"x":1}\n\n', b'{"x":1,"x":2}\n', b' ' * 16386, b'{"x":1}\n' * 4097):
        path.write_bytes(raw)
        with pytest.raises(ValueError):
            read_dataset(path)


def test_strict_wire_roundtrip_and_metadata():
    tree = MerkleTree([encode_record({"id": i}) for i in range(7)])
    head = head_document(tree.head)
    assert parse_head(head) == tree.head
    proof = proof_document(tree, "inclusion", 3)
    assert parse_proof(proof, "inclusion") == (7, 3, tree.inclusion(3))
    for key, value in (("format", "wrong"), ("encoding", "wrong"), ("size", True), ("root", "F" * 64)):
        with pytest.raises(ValueError):
            parse_head(dict(head, **{key: value}))
    with pytest.raises(ValueError):
        parse_head(dict(head, extra=1))
    for key, value in (("kind", "consistency"), ("index", True), ("size", -1), ("siblings", ["00"]), ("siblings", [] * 0 + ["00" * 32] * 14)):
        with pytest.raises(ValueError):
            parse_proof(dict(proof, **{key: value}), "inclusion")
