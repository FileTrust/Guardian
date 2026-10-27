"""Docker entry point using the same protected, one-node Guardian runtime."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import stat
import sys
import time

APP = Path(__file__).resolve().parent
STATE = Path('/var/lib/filetrust-guardian')
CREDENTIAL = Path('/etc/filetrust-guardian/unlock.key')
RUNTIME = Path('/run/filetrust-guardian')


def health():
    """Workers reached readiness in this container, not a previous instance."""
    try:
        started = json.loads((RUNTIME / 'container-start.json').read_text())
        ready = json.loads((STATE / '.filetrust-node-health.json').read_text())
        if ready['pid'] != started['pid'] or ready['ready_at'] < started['started_at']:
            return False
        if ready['version'] != (APP / 'VERSION').read_text().strip():
            return False
        os.kill(ready['pid'], 0)
        return True
    except (OSError, ValueError, TypeError, KeyError):
        return False


def stage_token(stream):
    from github_auth import validate_token
    raw = stream.read(8193)
    if len(raw) > 8192:
        raise ValueError('GitHub credential exceeds size limit')
    token = validate_token(raw.decode())
    fd = os.open(RUNTIME / 'github-token', os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as output:
        output.write(token)


def load_token():
    from github_auth import validate_token
    path = RUNTIME / 'github-token'
    if not path.exists():
        return
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError('GitHub credential must be an owner-only regular file')
        raw = os.read(fd, 8193)
        if len(raw) > 8192:
            raise ValueError('GitHub credential exceeds size limit')
        os.environ['GH_TOKEN'] = validate_token(raw.decode())
    finally:
        os.close(fd)
        path.unlink()


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['install', 'run', 'doctor', 'check', 'network-config', 'claim-dkg', 'health', 'idle', 'stage-token'])
    parser.add_argument('arguments', nargs=argparse.REMAINDER)
    args = parser.parse_args(arguments)
    if args.command == 'health':
        return 0 if health() else 1
    if args.command == 'idle':
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
        while True:
            signal.pause()
    if args.command == 'stage-token':
        stage_token(sys.stdin.buffer)
        return 0
    if args.command == 'run':
        (RUNTIME / 'container-start.json').write_text(json.dumps({'pid': os.getpid(), 'started_at': time.time()}))
        # No setup credential enters the running node's environment.
        os.environ.pop('GH_TOKEN', None)
        os.environ.pop('GITHUB_TOKEN', None)
    else:
        load_token()
    if args.command == 'check':
        from ft_updates import cli
        sys.argv = [str(APP / 'update.py'), *args.arguments]
        return cli(APP)
    if args.command == 'network-config':
        from ft_network_config import cli
        return cli(APP, [*args.arguments, '--home', str(STATE)])
    if any(a == '--service' or a.startswith(('--home', '--key-file')) for a in args.arguments):
        raise ValueError('Docker manages service and custody paths; use --profile, --release or --config-url for installation settings')
    os.execv(sys.executable, [sys.executable, '-u', str(APP / 'guardian.py'),
                            '--home', str(STATE), '--key-file', str(CREDENTIAL), args.command, *args.arguments])


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (Exception, KeyboardInterrupt) as exc:
        print('Guardian container stopped: ' + (str(exc) if isinstance(exc, (ValueError, PermissionError)) else type(exc).__name__), file=sys.stderr)
        raise SystemExit(1)
