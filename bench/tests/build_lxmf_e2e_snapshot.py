#!/usr/bin/env python3
"""Build/stage matched test binaries without overwriting an earlier lab's bind mounts.

Uses the actual crate through cargo_fork.sh. No temporary manifests, release build,
device install or deployment. OUT must not already exist; failed evidence is kept.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


ROOT = Path(__file__).resolve().parents[2]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inputs(fork):
    pin = (ROOT / "deploy/leviculum.ref").read_text().strip()
    head = subprocess.check_output(["git", "-C", str(fork), "rev-parse", "HEAD"], text=True).strip()
    dirty = subprocess.check_output(["git", "-C", str(fork), "status", "--porcelain"], text=True)
    if head != pin or dirty:
        raise RuntimeError("fork must be clean and match deploy/leviculum.ref")
    crate = ROOT / "bench/rns-iroh-node"
    files = list((crate / "src").rglob("*.rs")) + list((crate / "examples").rglob("*.rs"))
    files += [crate / "Cargo.toml", crate / "Cargo.lock", ROOT / "deploy/leviculum.ref",
              ROOT / "bench/cargo_fork.sh", ROOT / "bench/fork-patch.sh"]
    # Record the runtime fixture too; a later run must report any subsequent fixture changes.
    files += list((ROOT / "bench/tests").glob("lxmf*.py"))
    files += [ROOT / "bench/tests/client_admin_trust_sync_regression.py"]
    for path in files:
        if not path.resolve().is_relative_to(ROOT):
            raise RuntimeError("source input resolves outside the repository")
    return {"fork": head, "files": {str(p.relative_to(ROOT)): digest(p) for p in sorted(set(files))}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("out", type=Path, help="new private directory; existing paths are refused")
    parser.add_argument("--target", type=Path, default=Path.home() / ".cache/knothop-target/lxe2e-debug")
    args = parser.parse_args()
    if os.environ.get("CARGO_BUILD_TARGET"):
        raise RuntimeError("unset CARGO_BUILD_TARGET: this helper stages host test executables only")
    out = args.out.expanduser().absolute()
    fork = Path(os.environ.get("LEVICULUM_FORK", str(Path.home() / "dev/leviculum"))).expanduser().absolute()
    before = inputs(fork)
    out.mkdir(mode=0o700, parents=False, exist_ok=False)
    (out / "INCOMPLETE").write_text("Do not run tests from an incomplete snapshot.\n")
    env = dict(os.environ, CARGO_TARGET_DIR=str(args.target.expanduser().absolute()), LEVICULUM_FORK=str(fork))
    command = ["bash", str(ROOT / "bench/cargo_fork.sh"), "rns-iroh-node", "build", "--offline", "--locked",
               "--bin", "knothopd", "--example", "lxmf_host_access_e2e_driver"]
    with (out / "build.log").open("x") as log:
        os.chmod(log.name, 0o600)
        subprocess.run(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
    if inputs(fork) != before:
        raise RuntimeError("inputs changed during build; snapshot remains INCOMPLETE")
    target = args.target.expanduser().absolute() / "debug"
    artifacts = {}
    for source, name in ((target / "knothopd", "knothopd"),
                         (target / "examples/lxmf_host_access_e2e_driver", "driver")):
        initial = digest(source)
        shutil.copyfile(source, out / name)
        os.chmod(out / name, 0o500)
        if digest(source) != initial or digest(out / name) != initial:
            raise RuntimeError("binary changed while staging; snapshot remains INCOMPLETE")
        artifacts[name] = initial
    if inputs(fork) != before:
        raise RuntimeError("inputs changed while staging; snapshot remains INCOMPLETE")
    # Preserve the exact source/fixture bytes for later diagnosis. These are archival
    # inputs, not temporary/rewritten Cargo manifests and never used for this build.
    for relative, expected in before["files"].items():
        archived = out / "source-inputs" / relative
        archived.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, archived)
        os.chmod(archived, 0o400)
        if digest(archived) != expected:
            raise RuntimeError("source changed while archiving; snapshot remains INCOMPLETE")
    if inputs(fork) != before:
        raise RuntimeError("inputs changed while archiving; snapshot remains INCOMPLETE")
    manifest = {"inputs": before, "artifacts": artifacts, "kind": "debug E2E snapshot, not release/deployment"}
    path = out / "manifest.json"
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    os.chmod(path, 0o400)
    (out / "INCOMPLETE").unlink()
    print(json.dumps({"out": str(out), "manifest_sha256": digest(path), "artifacts": artifacts}))


if __name__ == "__main__":
    main()
