import json
from pathlib import Path
import subprocess
import sys

import pytest


def call(tmp_path, *args):
    return subprocess.run([sys.executable, "-m", "prefix_merkle.cli", *map(str, args)], cwd=tmp_path, text=True, capture_output=True)


def save(path, content):
    path.write_text(content)
    return path


def test_complete_installed_cli_roundtrip_and_failures(tmp_path):
    rows = [json.dumps({"id": i, "value": 3 * i}) for i in range(7)]
    old = save(tmp_path / "old.jsonl", "\n".join(rows[:3]) + "\n")
    new = save(tmp_path / "new.jsonl", "\n".join(rows) + "\n")
    old_head = save(tmp_path / "old-head.json", call(tmp_path, "head", old).stdout)
    new_head = save(tmp_path / "new-head.json", call(tmp_path, "head", new).stdout)
    inclusion = call(tmp_path, "inclusion", new, "--index", "2")
    consistency = call(tmp_path, "consistency", new, "--old-size", "3")
    assert inclusion.returncode == consistency.returncode == 0
    ipath = save(tmp_path / "inclusion.json", inclusion.stdout)
    cpath = save(tmp_path / "consistency.json", consistency.stdout)
    record = save(tmp_path / "record.json", rows[2])
    inc_args = ("verify-inclusion", "--head", new_head, "--record", record, "--proof", ipath)
    con_args = ("verify-consistency", "--old-head", old_head, "--new-head", new_head, "--proof", cpath)
    assert json.loads(call(tmp_path, *inc_args).stdout)["verified"] is True
    assert json.loads(call(tmp_path, *con_args).stdout)["verified"] is True
    record.write_text(rows[1])
    result = call(tmp_path, *inc_args)
    assert result.returncode == 1 and json.loads(result.stdout)["verified"] is False
    proof = json.loads(cpath.read_text())
    proof["old_size"] = 2
    cpath.write_text(json.dumps(proof))
    result = call(tmp_path, *con_args)
    assert result.returncode == 1 and json.loads(result.stdout)["verified"] is False
    proof["extra"] = "not accepted"
    cpath.write_text(json.dumps(proof))
    assert call(tmp_path, *con_args).returncode == 2


@pytest.mark.parametrize("data", ['{"x":1,"x":2}\n', '{"x":0.1}\n', '{"x":NaN}\n'])
def test_cli_rejects_invalid_dataset(tmp_path, data):
    path = save(tmp_path / "invalid.jsonl", data)
    result = call(tmp_path, "head", path)
    assert result.returncode == 2 and "error:" in result.stderr
