"""Deterministic synthetic records, tampering cases, and exact proof-byte counts."""

import argparse
import json
from pathlib import Path
from statistics import median

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from prefix_merkle import MerkleTree, encode_record, verify_consistency, verify_inclusion
from prefix_merkle.records import head_document, proof_document


def synthetic_records(size):
    return [{"id": i, "tick": 1000000 + 60 * i, "value": (37 * i + 11) % 101 - 50,
             "group": ["alpha", "beta", "gamma"][i % 3], "valid": i % 11 != 0} for i in range(size)]


def dump(path, data):
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, allow_nan=False) + "\n", encoding="utf-8")


def run(output):
    output.mkdir(parents=True, exist_ok=True)
    records = synthetic_records(257)
    leaves = [encode_record(row) for row in records]
    tree = MerkleTree(leaves)
    old = MerkleTree(leaves[:128])
    index = 17
    (output / "old.jsonl").write_bytes(b"\n".join(leaves[:128]) + b"\n")
    (output / "new.jsonl").write_bytes(b"\n".join(leaves) + b"\n")
    dump(output / "record.json", records[index])
    dump(output / "old-head.json", head_document(old.head))
    dump(output / "new-head.json", head_document(tree.head))
    dump(output / "inclusion.json", proof_document(tree, "inclusion", index))
    dump(output / "consistency.json", proof_document(tree, "consistency", 128))

    changed = leaves.copy()
    changed[index] = encode_record(dict(records[index], value=999))
    rewritten = MerkleTree(changed)
    swapped = leaves.copy()
    swapped[0], swapped[1] = swapped[1], swapped[0]
    reordered = MerkleTree(swapped)
    duplicate_suffix = MerkleTree(leaves + [leaves[7]])
    tests = {
        "valid_inclusion": verify_inclusion(leaves[index], index, tree.head, tree.inclusion(index)),
        "valid_append_128_to_257": verify_consistency(old.head, tree.head, tree.consistency(128)),
        "changed_record_against_original_head": verify_inclusion(changed[index], index, tree.head, rewritten.inclusion(index)),
        "rewritten_prefix_against_saved_old_head": verify_consistency(old.head, rewritten.head, rewritten.consistency(128)),
        "reordered_prefix_against_saved_old_head": verify_consistency(old.head, reordered.head, reordered.consistency(128)),
        "extra_proof_node": verify_consistency(old.head, tree.head, tree.consistency(128) + (b"x" * 32,)),
        "rewritten_record_against_substituted_head": verify_inclusion(changed[index], index, rewritten.head, rewritten.inclusion(index)),
        "duplicate_id_in_appended_suffix": verify_consistency(old.head, duplicate_suffix.head, duplicate_suffix.consistency(128)),
    }
    assert tests == {"valid_inclusion": True, "valid_append_128_to_257": True,
                     "changed_record_against_original_head": False, "rewritten_prefix_against_saved_old_head": False,
                     "reordered_prefix_against_saved_old_head": False, "extra_proof_node": False,
                     "rewritten_record_against_substituted_head": True, "duplicate_id_in_appended_suffix": True}

    sizes = [1, 2, 3, 5, 8, 13, 32, 64, 100, 256, 511, 1024, 4096]
    scaling = []
    for size in sizes:
        values = [encode_record(row) for row in synthetic_records(size)]
        candidate = MerkleTree(values)
        inclusion_sizes, consistency_sizes = [], []
        for i, value in enumerate(values):
            proof = candidate.inclusion(i)
            assert verify_inclusion(value, i, candidate.head, proof)
            inclusion_sizes.append(32 * len(proof))
        for m in range(1, size):
            proof = candidate.consistency(m)
            assert verify_consistency(candidate.prefix_head(m), candidate.head, proof)
            consistency_sizes.append(32 * len(proof))
        scaling.append({"records": size, "canonical_jsonl_bytes": sum(len(row) + 1 for row in values),
                        "inclusion_min_digest_bytes": min(inclusion_sizes),
                        "inclusion_median_digest_bytes": median(inclusion_sizes),
                        "inclusion_max_digest_bytes": max(inclusion_sizes),
                        "consistency_max_digest_bytes": max(consistency_sizes, default=0)})
    inclusion_doc = proof_document(tree, "inclusion", index)
    consistency_doc = proof_document(tree, "consistency", 128)
    metrics = {"data": "deterministic synthetic records; no external/private dataset",
               "old_head": head_document(old.head), "new_head": head_document(tree.head),
               "checks": tests, "scaling": scaling,
               "example_proof_sizes": {"inclusion_digest_bytes": len(tree.inclusion(index)) * 32,
                                       "consistency_digest_bytes": len(tree.consistency(128)) * 32,
                                       "inclusion_pretty_json_bytes": len((json.dumps(inclusion_doc, indent=2) + "\n").encode()),
                                       "consistency_pretty_json_bytes": len((json.dumps(consistency_doc, indent=2) + "\n").encode())},
               "interpretation": "Trust the saved heads separately. Proofs do not authenticate sources or enforce unique IDs, factual accuracy, or dataset completeness."}
    dump(output / "metrics.json", metrics)

    plt.rcParams.update({"font.size": 10, "axes.spines.top": False, "axes.spines.right": False})
    fig, axes = plt.subplots(1, 2, figsize=(12, 4.7), layout="constrained")
    ax = axes[0]
    ax.plot(sizes, [r["inclusion_max_digest_bytes"] for r in scaling], "o-", label="Max inclusion proof", color="#147d92")
    ax.plot(sizes, [r["consistency_max_digest_bytes"] for r in scaling], "s--", label="Max nontrivial prefix proof", color="#bf7717")
    ax.set_xscale("log", base=2)
    ax.set_xlabel("Number of synthetic records")
    ax.set_ylabel("Digest bytes only (32 bytes per node)")
    ax.set_title("Proof payload grows slowly with dataset size")
    ax.legend()
    ax.grid(alpha=0.2)
    ax = axes[1]
    counts = [len(tree.inclusion(i)) for i in range(tree.head.size)]
    lengths = sorted(set(counts))
    bars = ax.bar([str(n) for n in lengths], [counts.count(n) for n in lengths], color="#147d92", width=0.55)
    ax.bar_label(bars)
    ax.set_ylim(0, 285)
    ax.set_xlabel("Sibling digests in an inclusion proof")
    ax.set_ylabel("Number of records")
    ax.set_title("257 leaves: the final leaf has a shorter path")
    fig.suptitle("Prefix Merkle audit | Exact byte counts, no timing benchmark", fontsize=14)
    fig.savefig(output / "proof_sizes.png", dpi=170)
    plt.close(fig)
    print(json.dumps({"checks": tests, "largest_tree": scaling[-1], "example_proof_sizes": metrics["example_proof_sizes"]}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("results"))
    run(parser.parse_args().output)
