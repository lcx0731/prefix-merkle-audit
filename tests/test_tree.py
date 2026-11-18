from hashlib import sha256

import pytest

from prefix_merkle import EMPTY_ROOT, MerkleTree, TreeHead, leaf_hash, node_hash, verify_consistency, verify_inclusion


def reference_root(leaves):
    """Independent binary-carry frontier; no recursive interval splitting."""
    frontier = []
    for value in leaves:
        height, digest = 0, sha256(b"\x00" + value).digest()
        while frontier and frontier[-1][0] == height:
            _, left = frontier.pop()
            digest = sha256(b"\x01" + left + digest).digest()
            height += 1
        frontier.append((height, digest))
    if not frontier:
        return sha256(b"").digest()
    current = frontier.pop()[1]
    while frontier:
        current = sha256(b"\x01" + frontier.pop()[1] + current).digest()
    return current


def reference_consistency(m, n, old, new, path):
    """Independent bottom-up bit walk, rather than the production recursion."""
    if m == 0:
        return old == sha256(b"").digest() and not path
    if m == n:
        return old == new and not path
    first, last = m - 1, n - 1
    while first & 1:
        first >>= 1
        last >>= 1
    nodes = list(path)
    if first == 0:
        before = after = old
    else:
        before = after = nodes.pop(0)
    for digest in nodes:
        if not last:
            return False
        if first & 1 or first == last:
            before = sha256(b"\x01" + digest + before).digest()
            after = sha256(b"\x01" + digest + after).digest()
            while first and not first & 1:
                first >>= 1
                last >>= 1
        else:
            after = sha256(b"\x01" + after + digest).digest()
        first >>= 1
        last >>= 1
    return last == 0 and before == old and after == new


@pytest.mark.parametrize("size", [0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65])
def test_every_inclusion_and_prefix_against_independent_references(size):
    leaves = [f"synthetic-{i}".encode() for i in range(size)]
    tree = MerkleTree(leaves)
    assert tree.head.root == reference_root(leaves)
    for index, leaf in enumerate(leaves):
        proof = tree.inclusion(index)
        assert len(proof) <= (size - 1).bit_length()
        assert verify_inclusion(leaf, index, tree.head, proof)
        assert not verify_inclusion(leaf + b"!", index, tree.head, proof)
        assert not verify_inclusion(leaf, index, tree.head, proof + (b"x" * 32,))
        if proof:
            assert not verify_inclusion(leaf, index, tree.head, proof[:-1])
    for old_size in range(size + 1):
        old = TreeHead(old_size, reference_root(leaves[:old_size]))
        assert tree.prefix_head(old_size) == old
        proof = tree.consistency(old_size)
        assert verify_consistency(old, tree.head, proof)
        assert reference_consistency(old_size, size, old.root, tree.head.root, proof)
        assert len(proof) <= (size - 1).bit_length() + 1 if size else not proof
        assert not verify_consistency(old, tree.head, proof + (b"x" * 32,))
        if proof:
            assert not verify_consistency(old, tree.head, proof[:-1])
            for j in range(len(proof)):
                corrupt = proof[:j] + (bytes([proof[j][0] ^ 1]) + proof[j][1:],) + proof[j + 1:]
                assert not verify_consistency(old, tree.head, corrupt)


def test_small_hand_constructed_shapes_and_domain_separation():
    a, b, c, d, e = [sha256(b"\x00" + x).digest() for x in (b"a", b"b", b"c", b"d", b"e")]
    pair = lambda x, y: sha256(b"\x01" + x + y).digest()
    assert MerkleTree([b"a", b"b", b"c"]).head.root == pair(pair(a, b), c)
    five = MerkleTree([b"a", b"b", b"c", b"d", b"e"])
    assert five.head.root == pair(pair(pair(a, b), pair(c, d)), e)
    assert five.inclusion(4) == (pair(pair(a, b), pair(c, d)),)
    assert leaf_hash(b"") != EMPTY_ROOT
    assert leaf_hash(a + b) != node_hash(a, b)


@pytest.mark.parametrize("old_size", [1, 2, 3, 5, 8, 9, 16])
def test_rewritten_prefix_and_reordered_records_fail(old_size):
    leaves = [bytes([i]) for i in range(20)]
    old = MerkleTree(leaves[:old_size]).head
    corrupted = leaves.copy()
    corrupted[old_size - 1] = b"changed"
    tree = MerkleTree(corrupted)
    assert not verify_consistency(old, tree.head, tree.consistency(old_size))
    tree = MerkleTree(list(reversed(leaves)))
    assert not verify_consistency(old, tree.head, tree.consistency(old_size))


def test_inclusion_does_not_establish_dataset_completeness_or_unique_ids():
    duplicate = MerkleTree([b"same", b"same", b"other"])
    for index in (0, 1):
        assert verify_inclusion(b"same", index, duplicate.head, duplicate.inclusion(index))
    original = MerkleTree([b"visible", b"omitted"])
    subset = MerkleTree([b"visible"])
    assert verify_inclusion(b"visible", 0, subset.head, ())
    assert not verify_consistency(original.head, subset.head, ())
    assert not verify_inclusion(b"visible", 0, original.head, ())


def test_equal_size_and_empty_prefix_semantics():
    a, b = MerkleTree([b"a"]), MerkleTree([b"b"])
    empty = MerkleTree([])
    assert verify_consistency(a.head, a.head, ())
    assert not verify_consistency(a.head, b.head, ())
    assert verify_consistency(empty.head, a.head, ())
    assert not verify_inclusion(b"", 0, empty.head, ())
    with pytest.raises(ValueError):
        TreeHead(0, b"x" * 32)


def test_positions_sizes_and_proof_types_are_bound():
    tree = MerkleTree([b"a", b"b", b"c", b"d", b"e"])
    proof = tree.inclusion(2)
    assert not verify_inclusion(b"c", 1, tree.head, proof)
    assert not verify_inclusion(b"c", 2, TreeHead(4, tree.head.root), proof)
    for invalid in ([b"short"], [b"x" * 32] * 14, "abc", None):
        assert not verify_inclusion(b"a", 0, tree.head, invalid)
        assert not verify_consistency(tree.prefix_head(3), tree.head, invalid)
    for invalid in (-1, True, 5, 1.0):
        with pytest.raises(ValueError):
            tree.inclusion(invalid)
    for invalid in (-1, True, 6, 1.0):
        with pytest.raises(ValueError):
            tree.consistency(invalid)


def test_largest_supported_tree_and_resource_limits():
    tree = MerkleTree([str(i).encode() for i in range(4096)])
    for old_size in (1, 2047, 2048, 4095, 4096):
        assert verify_consistency(tree.prefix_head(old_size), tree.head, tree.consistency(old_size))
    assert len(tree.inclusion(4095)) == 12
    with pytest.raises(ValueError):
        MerkleTree([b""] * 4097)
    with pytest.raises(ValueError):
        MerkleTree([b"x" * 16385])
    with pytest.raises(ValueError):
        MerkleTree([b"x" * 16384] * 513)


@pytest.mark.parametrize("size", [-1, 4097, True, 1.0])
def test_invalid_heads(size):
    with pytest.raises(ValueError):
        TreeHead(size, b"x" * 32)
