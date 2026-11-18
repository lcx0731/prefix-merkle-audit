"""Create and verify bounded local Merkle artifacts. Roots are not signatures."""

import argparse
import json

from . import encode_record, verify_consistency, verify_inclusion
from .records import head_document, parse_head, parse_proof, proof_document, read_dataset, read_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("head", "inclusion", "consistency"):
        command = commands.add_parser(name)
        command.add_argument("dataset")
        if name == "inclusion":
            command.add_argument("--index", type=int, required=True)
        elif name == "consistency":
            command.add_argument("--old-size", type=int, required=True)
    inclusion = commands.add_parser("verify-inclusion")
    inclusion.add_argument("--head", required=True)
    inclusion.add_argument("--record", required=True)
    inclusion.add_argument("--proof", required=True)
    consistency = commands.add_parser("verify-consistency")
    consistency.add_argument("--old-head", required=True)
    consistency.add_argument("--new-head", required=True)
    consistency.add_argument("--proof", required=True)
    args = parser.parse_args()
    try:
        if args.command in ("head", "inclusion", "consistency"):
            tree = read_dataset(args.dataset)
            if args.command == "head":
                result = head_document(tree.head)
            else:
                value = args.index if args.command == "inclusion" else args.old_size
                result = proof_document(tree, args.command, value)
        elif args.command == "verify-inclusion":
            head = parse_head(read_json(args.head, 4096))
            size, index, siblings = parse_proof(read_json(args.proof), "inclusion")
            record = encode_record(read_json(args.record))
            result = {"verified": size == head.size and verify_inclusion(record, index, head, siblings)}
        else:
            old = parse_head(read_json(args.old_head, 4096))
            new = parse_head(read_json(args.new_head, 4096))
            size, old_size, siblings = parse_proof(read_json(args.proof), "consistency")
            result = {"verified": size == new.size and old_size == old.size and verify_consistency(old, new, siblings)}
        print(json.dumps(result, indent=2, allow_nan=False))
        if result.get("verified") is False:
            raise SystemExit(1)
    except (ValueError, TypeError, OSError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
