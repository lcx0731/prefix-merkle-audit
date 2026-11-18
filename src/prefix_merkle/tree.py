"""Domain-separated ordered Merkle trees and strict proof verification.

The tree construction follows the mathematical definitions in RFC 9162 §2.1.
This is original code, not a Certificate Transparency protocol implementation.
"""

from dataclasses import dataclass
from hashlib import sha256
from hmac import compare_digest

MAX_LEAVES = 4096
MAX_LEAF_BYTES = 16384
MAX_TOTAL_BYTES = 8 * 1024 * 1024
MAX_PROOF_NODES = 13
EMPTY_ROOT = sha256(b"").digest()


def _size(value):
    if type(value) is not int or not 0 <= value <= MAX_LEAVES:
        raise ValueError("tree size must be an integer in 0..4096")


def _digest(value):
    if type(value) is not bytes or len(value) != 32:
        raise ValueError("a digest must be exactly 32 bytes")
    return value


def leaf_hash(data):
    if type(data) is not bytes or len(data) > MAX_LEAF_BYTES:
        raise ValueError("a leaf must be bytes of length at most 16384")
    return sha256(b"\x00" + data).digest()


def node_hash(left, right):
    return sha256(b"\x01" + _digest(left) + _digest(right)).digest()


def _split(size):
    return 1 << ((size - 1).bit_length() - 1)


def _proof(nodes):
    if not isinstance(nodes, (tuple, list)) or len(nodes) > MAX_PROOF_NODES:
        raise ValueError("proof must contain at most 13 digests")
    return tuple(_digest(node) for node in nodes)


@dataclass(frozen=True)
class TreeHead:
    size: int
    root: bytes

    def __post_init__(self):
        _size(self.size)
        _digest(self.root)
        if self.size == 0 and self.root != EMPTY_ROOT:
            raise ValueError("empty tree must have the specified empty root")


class MerkleTree:
    """In-memory byte leaves, capped at 4096. Hashes are cached by interval.

    Build/proof generation is a reference implementation, not a log service.
    Leaves and public heads are immutable values. The private cache is internal.
    """

    def __init__(self, leaves):
        values, total = [], 0
        for data in leaves:
            if type(data) is not bytes or len(data) > MAX_LEAF_BYTES:
                raise ValueError("invalid leaf")
            total += len(data)
            if len(values) >= MAX_LEAVES or total > MAX_TOTAL_BYTES:
                raise ValueError("tree exceeds leaf-count or 8 MiB payload limit")
            values.append(data)
        self._leaves = tuple(values)
        self._cache = {}
        self._head = TreeHead(len(values), self._root(0, len(values)))

    @property
    def leaves(self):
        return self._leaves

    @property
    def head(self):
        return self._head

    def _root(self, start, size):
        key = start, size
        if key not in self._cache:
            if size == 0:
                value = EMPTY_ROOT
            elif size == 1:
                value = leaf_hash(self._leaves[start])
            else:
                split = _split(size)
                value = node_hash(self._root(start, split), self._root(start + split, size - split))
            self._cache[key] = value
        return self._cache[key]

    def prefix_head(self, size):
        _size(size)
        if size > self.head.size:
            raise ValueError("prefix size exceeds the tree")
        return TreeHead(size, self._root(0, size))

    def inclusion(self, index):
        if type(index) is not int or not 0 <= index < self.head.size:
            raise ValueError("index must address an existing leaf")

        def visit(start, size, offset):
            if size == 1:
                return ()
            split = _split(size)
            if offset < split:
                return visit(start, split, offset) + (self._root(start + split, size - split),)
            return visit(start + split, size - split, offset - split) + (self._root(start, split),)

        return visit(0, self.head.size, index)

    def consistency(self, old_size):
        _size(old_size)
        if old_size > self.head.size:
            raise ValueError("old size exceeds new size")
        if old_size == 0 or old_size == self.head.size:
            return ()

        def visit(start, size, prefix, root_known):
            if prefix == size:
                return () if root_known else (self._root(start, size),)
            split = _split(size)
            if prefix <= split:
                return visit(start, split, prefix, root_known) + (self._root(start + split, size - split),)
            return visit(start + split, size - split, prefix - split, False) + (self._root(start, split),)

        return visit(0, self.head.size, old_size, True)


def verify_inclusion(data, index, head, siblings):
    """False for invalid/mismatched proofs; head is supplied independently."""
    try:
        if not isinstance(head, TreeHead) or type(index) is not int or not 0 <= index < head.size:
            return False
        nodes = _proof(siblings)
        current = leaf_hash(data)
        # Derive left/right positions from the claimed index and size first.
        directions, offset, size = [], index, head.size
        while size > 1:
            split = _split(size)
            right = offset >= split
            directions.append(right)
            if right:
                offset, size = offset - split, size - split
            else:
                size = split
        if len(nodes) != len(directions):
            return False
        for right, sibling in zip(reversed(directions), nodes):
            current = node_hash(sibling, current) if right else node_hash(current, sibling)
        return compare_digest(current, head.root)
    except (ValueError, TypeError):
        return False


def verify_consistency(old, new, siblings):
    """Verify that old is an ordered prefix commitment of new.

    Empty prefixes prove nothing about any nonempty contents. Equal sizes require
    equal roots and an empty proof. No unused or missing proof nodes are accepted.
    """
    try:
        if not isinstance(old, TreeHead) or not isinstance(new, TreeHead) or old.size > new.size:
            return False
        nodes = _proof(siblings)
        if old.size == 0:
            return not nodes
        if old.size == new.size:
            return not nodes and compare_digest(old.root, new.root)
        cursor = 0

        def take():
            nonlocal cursor
            if cursor == len(nodes):
                raise ValueError("missing proof node")
            value = nodes[cursor]
            cursor += 1
            return value

        def rebuild(prefix, size, root_known):
            if prefix == size:
                root = old.root if root_known else take()
                return root, root
            split = _split(size)
            if prefix <= split:
                before, left = rebuild(prefix, split, root_known)
                return before, node_hash(left, take())
            before, right = rebuild(prefix - split, size - split, False)
            left = take()
            return node_hash(left, before), node_hash(left, right)

        previous, current = rebuild(old.size, new.size, True)
        return cursor == len(nodes) and compare_digest(previous, old.root) and compare_digest(current, new.root)
    except (ValueError, TypeError):
        return False
