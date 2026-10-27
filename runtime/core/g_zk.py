"""ZoKrates integration and Groth16 proof utilities.

Handles:
  - ZoKrates binary discovery and availability checks
  - V2 PRE partial proof generation (Baby Jubjub DLEQ, Groth16)
  - Share-possession proof generation (Baby Jubjub DLEQ, Groth16)
  - Proof struct conversion for on-chain submission
  - zkDKG dispute justification via proof tuple
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# ZoKrates binary resolution
# ---------------------------------------------------------------------------

def _zokrates_candidates(configured: str | None = None) -> list[str]:
    candidates: list[str] = []
    env_value = os.environ.get("ZOKRATES_BIN", "")
    if env_value:
        candidates.append(env_value)
    if configured:
        candidates.append(str(configured))
    # Bundled binary inside core/zk/ — highest priority after explicit config.
    _bundled = Path(__file__).resolve().parent / "zk" / "zokrates"
    if _bundled.is_file():
        candidates.append(str(_bundled))
    candidates.append("zokrates")
    deduped: list[str] = []
    for c in candidates:
        if c and c not in deduped:
            deduped.append(c)
    return deduped


def zokrates_available(candidate: str) -> bool:
    if not candidate:
        return False
    path = Path(str(candidate)).expanduser()
    if path.is_absolute() or "/" in str(candidate):
        return path.is_file() and os.access(path, os.X_OK)
    return shutil.which(str(candidate)) is not None


def resolve_zokrates_bin(configured: str | None = None) -> str:
    for candidate in _zokrates_candidates(configured):
        path = Path(candidate).expanduser()
        if path.is_absolute() or "/" in candidate:
            if path.is_file() and os.access(path, os.X_OK):
                return str(path)
            continue
        found = shutil.which(candidate)
        if found:
            return found
    return str(configured or os.environ.get("ZOKRATES_BIN") or "zokrates")


def zokrates_missing_message(configured: str | None = None) -> str:
    tried = ", ".join(_zokrates_candidates(configured))
    return (
        f"ZoKrates binary is not available. Tried: {tried}. "
        "Install ZoKrates or set ZOKRATES_BIN=/absolute/path/to/zokrates before starting Guardians."
    )


# ---------------------------------------------------------------------------
# Proof generation — calls ZoKrates directly (no shell script dependency)
# ---------------------------------------------------------------------------

def _run_zokrates(args: list[str], label: str, *, private_input: str | None = None) -> None:
    output_flag = "-o" if "compute-witness" in args else "--proof-path"
    # Keep any implicit auxiliary output (including out.wtns) in the same
    # private disposable directory as the witness, never the instance root.
    working_directory = Path(args[args.index(output_flag) + 1]).parent
    proc = subprocess.run(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        input=private_input,
        cwd=working_directory,
    )
    if proc.returncode != 0:
        # ZoKrates diagnostics can include witness values. Never forward them.
        raise RuntimeError(f"{label} failed with exit {proc.returncode}; private diagnostics suppressed")


def generate_v2_pre_proof(
    build_dir: Path,
    share: int,
    r: int,
    share_pub,
    c1,
    e1,
    e2,
    pk_req,
    context_hash: int,
    zokrates_bin: str = "zokrates",
) -> dict:
    """Generate a V2 PRE Groth16 proof.

    build_dir must contain: out, abi.json, proving.key
    (provided by the factory build or Guardian installer).
    """
    if share_pub is None or c1 is None or e1 is None or e2 is None or pk_req is None:
        raise ValueError("V2 proof points must not be infinity")
    zokrates_bin = resolve_zokrates_bin(zokrates_bin)
    build_dir = Path(build_dir)
    out = build_dir / "out"
    abi = build_dir / "abi.json"
    pk = build_dir / "proving.key"
    if not out.is_file():
        raise FileNotFoundError(f"Missing compiled V2 PRE circuit: {out}. Build or install the matching verified proof bundle first.")
    if not pk.is_file():
        raise FileNotFoundError(f"Missing V2 PRE proving key: {pk}")

    witness_args = [
        str(int(share)), str(int(r)),
        str(int(share_pub[0])), str(int(share_pub[1])),
        str(int(c1[0])), str(int(c1[1])),
        str(int(e1[0])), str(int(e1[1])),
        str(int(e2[0])), str(int(e2[1])),
        str(int(pk_req[0])), str(int(pk_req[1])),
        str(int(context_hash)),
    ]

    with tempfile.TemporaryDirectory(prefix="filetrust_v2_pre_") as tmp:
        tmpdir = Path(tmp)
        witness = tmpdir / "witness"
        proof = tmpdir / "proof.json"

        _run_zokrates(
            [zokrates_bin, "compute-witness",
             "-i", str(out), "-s", str(abi),
             "-o", str(witness), "--stdin"],
            "V2 PRE proof generation",
            private_input=" ".join(witness_args) + "\n",
        )
        _run_zokrates(
            [zokrates_bin, "generate-proof",
             "-i", str(out), "-p", str(pk),
             "-w", str(witness), "--proof-path", str(proof)],
            "V2 PRE proof generation",
        )
        return json.loads(proof.read_text(encoding="utf-8"))


def generate_share_possession_proof(
    build_dir: Path,
    share: int,
    share_pub,
    challenge_point,
    response_point,
    context_hash: int,
    zokrates_bin: str = "zokrates",
) -> dict:
    """Generate a share-possession Groth16 proof.

    build_dir must contain: out, abi.json, proving.key
    (provided by the factory build or Guardian installer).
    """
    if share_pub is None or challenge_point is None or response_point is None:
        raise ValueError("Share-possession proof points must not be infinity")
    zokrates_bin = resolve_zokrates_bin(zokrates_bin)
    build_dir = Path(build_dir)
    out = build_dir / "out"
    abi = build_dir / "abi.json"
    pk = build_dir / "proving.key"
    if not out.is_file():
        raise FileNotFoundError(f"Missing compiled share-possession circuit: {out}. Build or install the matching verified proof bundle first.")
    if not pk.is_file():
        raise FileNotFoundError(f"Missing share-possession proving key: {pk}")

    witness_args = [
        str(int(share)),
        str(int(share_pub[0])), str(int(share_pub[1])),
        str(int(challenge_point[0])), str(int(challenge_point[1])),
        str(int(response_point[0])), str(int(response_point[1])),
        str(int(context_hash)),
    ]

    with tempfile.TemporaryDirectory(prefix="filetrust_share_possession_") as tmp:
        tmpdir = Path(tmp)
        witness = tmpdir / "witness"
        proof = tmpdir / "proof.json"

        _run_zokrates(
            [zokrates_bin, "compute-witness",
             "-i", str(out), "-s", str(abi),
             "-o", str(witness), "--stdin"],
            "Share-possession proof generation",
            private_input=" ".join(witness_args) + "\n",
        )
        _run_zokrates(
            [zokrates_bin, "generate-proof",
             "-i", str(out), "-p", str(pk),
             "-w", str(witness), "--proof-path", str(proof)],
            "Share-possession proof generation",
        )
        return json.loads(proof.read_text(encoding="utf-8"))


def generate_zkdkg_dispute_justification_proof(
    build_dir: Path,
    commitments,
    secret_key: int,
    dealer_pub,
    receiver_pub,
    receiver_index: int,
    encrypted_share: int,
    public_input_hash: int,
    zokrates_bin: str = "zokrates",
) -> dict:
    """Generate a zkDKG encrypted-share dispute justification proof."""
    zokrates_bin = resolve_zokrates_bin(zokrates_bin)
    build_dir = Path(build_dir)
    out = build_dir / "out"
    abi = build_dir / "abi.json"
    pk = build_dir / "proving.key"
    if not out.is_file():
        raise FileNotFoundError(f"Missing zkDKG dispute circuit: {out}. Build or install the matching verified proof bundle first.")
    if not pk.is_file():
        raise FileNotFoundError(f"Missing zkDKG dispute proving key: {pk}")

    witness_args: list[str] = []
    for point in commitments:
        witness_args.extend([str(int(point[0])), str(int(point[1]))])
    witness_args.extend([
        str(int(secret_key)),
        str(int(dealer_pub[0])), str(int(dealer_pub[1])),
        str(int(receiver_pub[0])), str(int(receiver_pub[1])),
        str(int(receiver_index)),
        str(int(encrypted_share)),
        str(int(public_input_hash)),
    ])

    with tempfile.TemporaryDirectory(prefix="filetrust_zkdkg_dispute_") as tmp:
        tmpdir = Path(tmp)
        witness = tmpdir / "witness"
        proof = tmpdir / "proof.json"

        _run_zokrates(
            [zokrates_bin, "compute-witness",
             "-i", str(out), "-s", str(abi),
             "-o", str(witness), "--stdin"],
            "zkDKG dispute justification proof generation",
            private_input=" ".join(witness_args) + "\n",
        )
        _run_zokrates(
            [zokrates_bin, "generate-proof",
             "-i", str(out), "-p", str(pk),
             "-w", str(witness), "--proof-path", str(proof)],
            "zkDKG dispute justification proof generation",
        )
        return json.loads(proof.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Proof struct helpers for on-chain submission
# ---------------------------------------------------------------------------

def v2_proof_struct(proof: dict) -> dict:
    """Convert a ZoKrates proof JSON to the on-chain Groth16 struct format."""
    p = proof.get("proof", proof)
    def n(value):
        return int(value, 0) if isinstance(value, str) else int(value)
    return {
        "a": {"X": n(p["a"][0]), "Y": n(p["a"][1])},
        "b": {
            "X": [n(p["b"][0][0]), n(p["b"][0][1])],
            "Y": [n(p["b"][1][0]), n(p["b"][1][1])],
        },
        "c": {"X": n(p["c"][0]), "Y": n(p["c"][1])},
    }


def proof_tuple_from_zokrates_json(proof_json: dict) -> tuple:
    """Convert ZoKrates proof JSON to the raw ((a),(b),(c)) tuple for disputes."""
    p = proof_json["proof"]
    def n(value):
        return int(value, 0) if isinstance(value, str) else int(value)
    return (
        (n(p["a"][0]), n(p["a"][1])),
        (
            (n(p["b"][0][0]), n(p["b"][0][1])),
            (n(p["b"][1][0]), n(p["b"][1][1])),
        ),
        (n(p["c"][0]), n(p["c"][1])),
    )
