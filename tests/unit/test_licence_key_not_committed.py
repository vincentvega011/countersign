"""The AG Studio licence key lives only in the environment (Decision 112).

Fails if the key from the environment or the local .env, or anything shaped like an AG licence key,
appears in a tracked file; if .env.example gives the variable a value; or if the dashboard build output
is not ignored. Matched text is never printed.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
NAME = "AG_STUDIO_LICENSE_KEY"
# AG licence keys end in a version and type marker, a base64 expiry and a 32 hex digit checksum.
SHAPED = re.compile(r"\[v\d+\]_\[[0-9A-Za-z]{2,8}\]_[A-Za-z0-9+/]{8,}={0,2}[0-9a-f]{32}")
LONG_TOKEN = re.compile(r"[A-Za-z0-9+/=_\-\[\]{}]{120,}")
ASSIGNED = re.compile(rf"{NAME}\s*[:=]\s*[\"']?[^\s\"'#]")


def _tracked() -> list[Path]:
    out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True)
    return [ROOT / p for p in out.stdout.decode().split("\0") if p]


def _local_key() -> str | None:
    value = os.environ.get(NAME, "").strip()
    env = ROOT / ".env"
    if not value and env.is_file():
        for line in env.read_text(errors="replace").splitlines():
            if line.startswith(f"{NAME}="):
                value = line.split("=", 1)[1].strip().strip("'\"")
    return value if len(value) >= 20 else None


def _texts() -> list[tuple[Path, str]]:
    found = []
    for path in _tracked():
        if (
            not path.is_file()
            or path.name in ("pnpm-lock.yaml", "uv.lock")
            or path.suffix == ".woff2"
        ):
            continue
        found.append((path, path.read_text(errors="ignore")))
    return found


def test_no_tracked_file_holds_the_key_or_a_licence_shaped_string() -> None:
    key = _local_key()
    leaks = []
    for path, text in _texts():
        rel = str(path.relative_to(ROOT))
        if key and key in text:
            leaks.append(f"{rel}: the local key")
        if SHAPED.search(text):
            leaks.append(f"{rel}: a licence-shaped string")
        if ASSIGNED.search(text) and not rel.endswith(".md"):
            leaks.append(f"{rel}: {NAME} assigned a value")
    assert not leaks, leaks


def test_licence_names_near_long_tokens_are_flagged() -> None:
    """No tracked file pairs the word licence with a long opaque token on one line."""
    bad = []
    for path, text in _texts():
        for line in text.splitlines():
            if re.search(r"licen[cs]e", line, re.IGNORECASE) and LONG_TOKEN.search(line):
                bad.append(str(path.relative_to(ROOT)))
                break
    assert not bad, bad


def test_the_example_names_the_variable_with_an_empty_value() -> None:
    lines = (ROOT / ".env.example").read_text().splitlines()
    assert any(re.fullmatch(rf"{NAME}=\s*(#.*)?", line) for line in lines)


def test_the_build_output_and_env_are_ignored() -> None:
    for path in ("web/dashboard/dist/index.html", ".env"):
        ignored = subprocess.run(["git", "check-ignore", "-q", path], cwd=ROOT, check=False)
        assert ignored.returncode == 0, path


def test_the_detectors_catch_a_synthetic_key() -> None:
    fake = "Fake_Company_NOT_A_KEY_[v3]_[0102]_" + "QUJDREVGR0g=" + "0" * 32
    assert SHAPED.search(fake)
    assert ASSIGNED.search(f"{NAME}=abc")
    assert not ASSIGNED.search(f"{NAME}=")
