#!/usr/bin/env python3
"""Verify all packaged fixed-link metadata without the release archives.

This is intentionally not a proof-replay completion gate.  Full verification
requires `verify_public_release.py` plus both pinned release archives.
"""

from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
PUBLIC_VERIFIER = HERE / "verify_public_release.py"


def load_public_verifier():
    spec = importlib.util.spec_from_file_location(
        "fixed_link_public_verifier", PUBLIC_VERIFIER
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load fixed-link public verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    args = parser.parse_args()
    if not __debug__:
        raise RuntimeError("structural verifier refuses optimized Python (-O)")
    verifier = load_public_verifier()
    root = verifier.checked_input_path(
        args.repo_root, "repository root", "directory"
    )
    production = verifier.checked_input_path(
        root / "certificates" / "fixed-link-campaign",
        "production directory",
        "directory",
    )
    proof = verifier.checked_input_path(
        root / "certificates" / "fixed-link-proof",
        "proof directory",
        "directory",
    )
    base = (
        root
        / "certificates"
        / "global"
        / "compact_campaign"
        / "global_base.cnf"
    )
    manifest, _body, _representatives = verifier.load_production(
        production, base
    )
    aggregate, receipts = verifier.load_receipts(proof, manifest)
    assets = verifier.load_release_assets(
        proof / "release-assets.json", aggregate, receipts
    )
    print(
        "STRUCTURAL PASS ONLY: 266 roots/receipts and both release-archive "
        "indexes are complete and hash-bound."
    )
    print(
        "Full proof replay was not run; supply both pinned archives to "
        "verify_public_release.py."
    )
    print("production=%s" % manifest["manifest_sha256"])
    print("aggregate=%s" % aggregate["aggregate_sha256"])
    print("release-assets=%s" % assets["release_assets_sha256"])
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print("ERROR: %s" % error, file=sys.stderr)
        raise SystemExit(2)
