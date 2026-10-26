"""Simulate a lost local ACK without changing the original signed admin request.

Test-only helper; mounted in the isolated E2E containers at /e2e.
Deleting the client journal and submitting again creates a NEW signed record/expiry,
which correctly conflicts with the server's request digest under the same ID.
"""
import copy
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time


def without_ack(record, now):
    request = record.get("request")
    if not isinstance(request, dict) or not isinstance(request.get("exp"), int):
        raise ValueError("missing original request")
    if request["exp"] <= now:
        raise ValueError("original request expired; cannot test identical replay")
    if record.get("durable_ack") is not True:
        raise ValueError("no confirmed local ACK to lose")
    pending = copy.deepcopy(record)
    pending.update(status="pending", durable_ack=False, result=None,
                   authenticated_envelope=None, updated=now)
    return pending


def lose_ack(path, now):
    path = Path(path)
    meta = path.lstat()
    if not stat.S_ISREG(meta.st_mode):
        raise ValueError("client journal is not a regular file")
    pending = without_ack(json.loads(path.read_text()), now)
    temp = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, prefix=".lost-ack-", delete=False) as f:
            temp = Path(f.name)
            os.fchmod(f.fileno(), 0o600)
            json.dump(pending, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
        temp = None
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if temp is not None:
            temp.unlink(missing_ok=True)


if __name__ == "__main__":
    try:
        lose_ack(sys.argv[1], int(time.time()))
    except (OSError, ValueError, KeyError, IndexError):
        # Never print the private journal or exception text containing its data.
        print("original_request_unavailable_or_expired")
        raise SystemExit(1)
    print("original_request_preserved")
