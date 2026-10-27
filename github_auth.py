"""Optional GitHub login for private downloads; public installs need no login."""
from __future__ import annotations

import os
import shutil
import subprocess


def validate_token(value):
    value = value.strip()
    if not value or len(value) > 8192 or any(ord(c) < 33 or ord(c) > 126 for c in value):
        raise ValueError("Invalid GitHub credential. Unset GH_TOKEN and GITHUB_TOKEN, then rerun using your saved GitHub login.")
    return value


def github_token():
    for name in ("GH_TOKEN", "GITHUB_TOKEN"):
        if os.environ.get(name):
            return validate_token(os.environ[name])
    if not shutil.which("gh"):
        return None
    prefixes = [[]]
    # sudo normally hides the caller's login. Read it as that caller, without
    # copying a credential file or depending on a particular CLI version.
    caller = os.environ.get("SUDO_USER")
    if os.geteuid() == 0 and caller and caller != "root" and shutil.which("runuser"):
        prefixes.insert(0, ["runuser", "-u", caller, "--"])
    for prefix in prefixes:
        for command in (["gh", "auth", "token"],
                        ["gh", "config", "get", "oauth_token", "--host", "github.com"]):
            try:
                result = subprocess.run(prefix + command, capture_output=True, text=True, timeout=10)
                if result.returncode == 0 and result.stdout.strip():
                    return validate_token(result.stdout)
            except (OSError, subprocess.TimeoutExpired):
                continue
    return None


if __name__ == "__main__":
    import sys
    try:
        token = github_token()
        if sys.argv[1:] == ["--print"]:
            # Used only over a pipe into a temporary container's private tmpfs.
            if sys.stdout.isatty():
                raise ValueError("Refusing to print a GitHub credential to a terminal")
            if token:
                sys.stdout.write(token)
        elif sys.argv[1:] != ["--check"]:
            raise ValueError("Use --check to validate optional download access")
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
