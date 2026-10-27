#!/usr/bin/env python3
"""Check signed application releases without changing the running app."""
from pathlib import Path
import os
import sys
from ft_updates import cli

if __name__ == "__main__":
    if not any(arg in sys.argv for arg in ('--status', '--help', '-h', '--authorize-service')):
        from github_auth import github_token
        try:
            token = github_token()
            if token:
                os.environ['GH_TOKEN'] = token
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            raise SystemExit(1)
    raise SystemExit(cli(Path(__file__).resolve().parent))
