"""Signed manifests, bounded resumable downloads, and strict ZIP extraction."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
import tarfile
import time
import zipfile
from pathlib import Path
from urllib.parse import urlparse

import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from github_auth import github_token

REPOSITORY = "FileTrust/Guardian"
TAG = "guardian-recovery-2026-10-28.1"
ZOKRATES_URL = "https://github.com/Zokrates/ZoKrates/releases/download/0.8.8/zokrates-0.8.8-x86_64-unknown-linux-gnu.tar.gz"
MAX_METADATA = 4 * 1024 * 1024


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(4 * 1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def verify_manifest(raw: bytes, signature: bytes, public_key: Path) -> dict:
    if len(raw) > MAX_METADATA:
        raise ValueError("Manifest too large")
    key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key.read_text().strip(), validate=True))
    key.verify(base64.b64decode(signature.strip(), validate=True), raw)
    data = json.loads(raw)
    if data.get("schema") != 1 or data.get("proof_system") != "g16" or data.get("curve") != "bn128":
        raise ValueError("Unsupported artifact manifest")
    if data.get("zokrates_version") != "0.8.8" or not isinstance(data.get("bundles"), list):
        raise ValueError("Unsupported ZoKrates release")
    origin = data.get('artifact_release')
    if origin is not None and (not isinstance(origin, str) or
            not re.fullmatch(r'[\w.-]{1,128}', origin)):
        raise ValueError('Invalid signed artifact release reference')
    seen = set()
    for bundle in data["bundles"]:
        name = bundle["id"]
        if name in seen or not re.fullmatch(r"zkdkg-n\d+-t\d+|v2_pre_partial|share_possession|runtime-linux-x86_64", name):
            raise ValueError("Invalid or duplicate bundle")
        seen.add(name)
        if name.startswith("zkdkg-"):
            n, t = bundle.get("n"), bundle.get("t")
            if type(n) is not int or type(t) is not int or not 2 <= t <= n <= 20 or name != f"zkdkg-n{n}-t{t}":
                raise ValueError("Invalid N/t profile metadata")
        if name.startswith("runtime-"):
            if bundle.get("url") != ZOKRATES_URL or bundle.get("archive") != "tar.gz" or bundle.get("member") != "zokrates":
                raise ValueError("Runtime must come from the pinned official ZoKrates release")
            if bundle["asset"] != "zokrates-0.8.8-x86_64-unknown-linux-gnu.tar.gz":
                raise ValueError("Unexpected upstream runtime asset")
        elif bundle["asset"] != name + ".zip" or bundle.get("url"):
            raise ValueError("Unsafe asset name")
        if not 0 < bundle["size"] < 2 * 1024**3:
            raise ValueError("Invalid archive size")
        expected = {"zokrates"} if name.startswith("runtime-") else {"out", "abi.json", "proving.key", "verification.key"}
        if set(bundle["files"]) != expected:
            raise ValueError("Unexpected public artifact files")
        for row in [bundle, *bundle["files"].values()]:
            if not re.fullmatch(r"[a-f0-9]{64}", row["sha256"]) or not 0 < row["size"] <= 4 * 1024**3:
                raise ValueError("Invalid artifact digest or size")
    return data


class GitHubRelease:
    def __init__(self, repository=REPOSITORY, tag=TAG):
        if not re.fullmatch(r"[\w.-]+/[\w.-]+", repository) or not re.fullmatch(r"[\w.-]+", tag):
            raise ValueError("Invalid release location")
        self.session = requests.Session()
        self.repository = repository
        self.artifact_release = None
        self._artifact_assets = None
        self.session.headers["User-Agent"] = "FileTrust-Guardian/1"
        self.token = github_token()
        try:
            metadata = self.small(f"https://api.github.com/repos/{repository}/releases/tags/{tag}", metadata=True)
            release = json.loads(metadata)
        except RuntimeError:
            if not self.token:
                raise
            # GitHub omits draft releases from the tag endpoint. Authorized
            # maintainers can still test them through the release listing.
            listing = json.loads(self.small(f"https://api.github.com/repos/{repository}/releases?per_page=100", metadata=True))
            release = next((row for row in listing if row["tag_name"] == tag), None)
            if not release:
                raise RuntimeError("Release unavailable for this GitHub account") from None
        self.assets = {row["name"]: row["url"] for row in release["assets"]}

    def response(self, url, **kwargs):
        if url != ZOKRATES_URL and (urlparse(url).scheme != "https" or urlparse(url).hostname != "api.github.com"):
            raise ValueError("Unexpected release API host")
        headers = dict(kwargs.pop("headers", {}))
        if self.token and urlparse(url).hostname == "api.github.com":
            headers["Authorization"] = "Bearer " + self.token
        # requests strips Authorization when following redirects to the asset CDN.
        response = self.session.get(url, headers=headers, stream=True, timeout=(20, 60), **kwargs)
        if response.status_code == 401 and "Authorization" in headers:
            # A stale private login must not prevent public downloads later.
            response.close()
            self.token = None
            headers.pop("Authorization")
            response = self.session.get(url, headers=headers, stream=True, timeout=(20, 60), **kwargs)
        if response.status_code in (401, 404):
            response.close()
            raise RuntimeError("Release unavailable. For private testing, run gh auth login first")
        response.raise_for_status()
        if urlparse(response.url).scheme != "https":
            response.close()
            raise RuntimeError("Insecure asset redirect")
        return response

    def small(self, url, metadata=False):
        with self.response(url, headers={"Accept": "application/vnd.github+json" if metadata else "application/octet-stream"}) as response:
            body = bytearray()
            for chunk in response.iter_content(65536):
                body.extend(chunk)
                if len(body) > MAX_METADATA:
                    raise ValueError("Release metadata too large")
            return bytes(body)

    def manifest(self, public_key):
        raw = self.small(self.assets["manifest.json"])
        signature = self.small(self.assets["manifest.sig"])
        manifest = verify_manifest(raw, signature, public_key)
        # Only signed metadata may select an existing release in THIS repo.
        # The current manifest still pins every archive and extracted digest.
        self.artifact_release = manifest.get('artifact_release')
        return manifest, raw, signature

    def download(self, bundle, cache, progress=print):
        assets = self.assets
        if not bundle.get('url') and self.artifact_release:
            if self._artifact_assets is None:
                self._artifact_assets = GitHubRelease(repository=self.repository,
                    tag=self.artifact_release).assets
            assets = self._artifact_assets
        url = bundle.get("url") or assets[bundle["asset"]]
        return download(self, url, bundle, cache, progress)


def download(remote, url, bundle, cache: Path, progress=print):
    cache.mkdir(parents=True, exist_ok=True)
    target = cache / (bundle["sha256"] + (".tar.gz" if bundle.get("archive") == "tar.gz" else ".zip"))
    partial = target.with_suffix(".part")
    if target.exists() and target.stat().st_size == bundle["size"] and digest(target) == bundle["sha256"]:
        progress("Cached bundle verified")
        return target
    target.unlink(missing_ok=True)
    for attempt in range(4):
        offset = partial.stat().st_size if partial.exists() else 0
        if offset > bundle["size"]:
            partial.unlink()
            offset = 0
        try:
            if offset < bundle["size"]:
                headers = {"Accept": "application/octet-stream", "Accept-Encoding": "identity"}
                if offset:
                    headers["Range"] = f"bytes={offset}-"
                with remote.response(url, headers=headers) as response:
                    if response.status_code == 206:
                        match = re.fullmatch(r"bytes (\d+)-(\d+)/(\d+)", response.headers.get("Content-Range", ""))
                        if not match or int(match[1]) != offset or int(match[3]) != bundle["size"]:
                            raise ValueError("Invalid download resume response")
                    elif response.status_code == 200:
                        offset = 0  # Server ignored Range: safely start over.
                    else:
                        raise ValueError("Unexpected download response")
                    last_percent = -1
                    with partial.open("ab" if offset else "wb") as output:
                        for chunk in response.iter_content(1024 * 1024):
                            offset += len(chunk)
                            if offset > bundle["size"]:
                                raise ValueError("Download exceeds signed size")
                            output.write(chunk)
                            percent = offset * 100 // bundle["size"]
                            if percent != last_percent:
                                progress(f"[{'#' * (percent // 5):<20}] {percent}% ({offset}/{bundle['size']} bytes)")
                                last_percent = percent
            if partial.stat().st_size != bundle["size"]:
                raise requests.ConnectionError("Download interrupted")
            if digest(partial) != bundle["sha256"]:
                partial.unlink()
                raise ValueError("Bundle checksum failed; rerun to download a clean copy")
            os.replace(partial, target)
            return target
        except (requests.RequestException, OSError):
            if attempt == 3:
                raise RuntimeError("Download interrupted; rerun installation to resume") from None
            time.sleep(min(2**attempt, 8))
    raise RuntimeError("Download failed")


def destination(root, bundle):
    if bundle["id"].startswith("zkdkg-"):
        return root / "zkdkg" / str(bundle["n"]) / f"t{bundle['t']}" / "poly_eval"
    return root / bundle["id"]


def installed(path, bundle):
    return path.is_dir() and all((path / name).is_file() and not (path / name).is_symlink()
                                and (path / name).stat().st_size == row["size"]
                                and digest(path / name) == row["sha256"]
                                for name, row in bundle["files"].items())


def extract(archive, target, bundle):
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".artifact-", dir=target.parent) as temporary:
        staging = Path(temporary) / "ready"
        staging.mkdir()
        if bundle.get("archive") == "tar.gz":
            # Extract only the signed regular executable. Never extract arbitrary
            # archive paths, links, or the upstream development/test directories.
            with tarfile.open(archive, "r:gz") as tar:
                members = [m for m in tar.getmembers() if m.name == bundle["member"]]
                row = bundle["files"]["zokrates"]
                if len(members) != 1 or not members[0].isfile() or members[0].size != row["size"]:
                    raise ValueError("Unexpected runtime tar member")
                with tar.extractfile(members[0]) as source, (staging / "zokrates").open("wb") as output:
                    shutil.copyfileobj(source, output, 1024 * 1024)
                if digest(staging / "zokrates") != row["sha256"]:
                    raise ValueError("Extracted runtime checksum failed")
                (staging / "zokrates").chmod(0o755)
        else:
            extract_zip(archive, staging, bundle)
        if target.exists():
            # Verified immutable artifact paths; no private state ever lives here.
            old = Path(temporary) / "old"
            os.replace(target, old)
            try:
                os.replace(staging, target)
            except BaseException:
                os.replace(old, target)
                raise
        else:
            os.replace(staging, target)


def extract_zip(archive, staging, bundle):
    with zipfile.ZipFile(archive) as z:
        entries = z.infolist()
        if len(entries) != len(bundle["files"]) or {e.filename for e in entries} != set(bundle["files"]):
            raise ValueError("ZIP contains unexpected files")
        for entry in entries:
            row = bundle["files"][entry.filename]
            mode = entry.external_attr >> 16
            if entry.file_size != row["size"] or (stat.S_IFMT(mode) not in (0, stat.S_IFREG)):
                raise ValueError("ZIP file type or size mismatch")
            with z.open(entry) as source, (staging / entry.filename).open("wb") as output:
                shutil.copyfileobj(source, output, 1024 * 1024)
            if digest(staging / entry.filename) != row["sha256"]:
                raise ValueError("Extracted artifact checksum failed")
            (staging / entry.filename).chmod(0o755 if entry.filename == "zokrates" else 0o644)
