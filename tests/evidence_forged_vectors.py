"""Signed but inconsistent evidence bundles as shared vectors (`tests/vectors/evidence/forged/`).

Every signature in these bundles is valid (each has its own throwaway keys, made by
`tests/evidence_forge.py`), and two signed things disagree. They exist so the browser verifier is held to
the checks that only such a bundle reaches (the Python tests build them at run time). The forger uses
fresh random keys and ECDSA is not deterministic, so the files are written once and committed;
`uv run python -m tests.evidence_forged_vectors` writes them again. Each is verified with its own keys
pinned. Only synthetic data: `cus_` ids, sandbox-shaped PayPal ids, `.example.test` sites.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from countersign_verify import verify
from tests.unit.test_verify_evidence import CASES, forged

DIRECTORY = Path(__file__).resolve().parent / "vectors" / "evidence"


def slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")


def own_keys(bundle: dict[str, Any]) -> dict[str, Any]:
    return {"merchant": bundle["keys"]["merchant"], "platform": bundle["keys"]["platform"]}


def first_failure(bundle: dict[str, Any]) -> tuple[str | None, str | None]:
    failed = [r for r in verify(bundle, own_keys(bundle)) if not r.ok]
    return (failed[0].name, failed[0].code) if failed else (None, None)


def build_all() -> dict[str, dict[str, Any]]:
    bundles = {"clean": forged(), "checkout_header_es384": forged(jwt_alg="ES384")}
    for name, (kw, _, _) in CASES.items():
        bundles[slug(name)] = forged(**kw)
    other = forged()
    other["mandates"]["checkout_open"] = forged()["mandates"]["checkout_open"]
    bundles["open_mandate_not_extended"] = other
    return bundles


def write_forged_vectors(directory: Path = DIRECTORY) -> list[dict[str, Any]]:
    out = directory / "forged"
    out.mkdir(parents=True, exist_ok=True)
    for old in out.glob("*.json"):
        old.unlink()
    entries = []
    for name, bundle in sorted(build_all().items()):
        (out / f"{name}.json").write_text(json.dumps(bundle, indent=1, sort_keys=True) + "\n")
        step, code = first_failure(bundle)
        entries.append({"file": f"forged/{name}.json", "first_failure": step, "code": code})
    index_path = directory / "index.json"
    index = json.loads(index_path.read_text())
    index["forged"] = entries
    index_path.write_text(json.dumps(index, indent=1, sort_keys=True) + "\n")
    return entries


if __name__ == "__main__":
    for entry in write_forged_vectors():
        print(entry)
