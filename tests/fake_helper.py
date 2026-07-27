#!/usr/bin/python3
"""A stand-in for oss-helper, so the streaming path can be tested without pkexec.

Emits progress lines on stderr and a JSON Result on stdout, exactly as the real
helper does, with the timing and volume configurable from argv. Nothing here
touches the system: it writes no files and runs no commands.

    fake_helper.py <payload.json> --lines N --delay SECONDS
                                  [--stderr-bytes N] [--exit CODE] [--silent]
"""

from __future__ import annotations

import argparse
import json
import sys
import time

PROGRESS_PREFIX = "@@ "


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("payload", nargs="?")
    parser.add_argument("--lines", type=int, default=5)
    parser.add_argument("--delay", type=float, default=0.0)
    #: Emit this much non-progress noise too. The real helper's stderr carries
    #: warnings from the commands it runs, and enough of it will fill the pipe
    #: buffer and deadlock anything that is not draining it.
    parser.add_argument("--stderr-bytes", type=int, default=0)
    parser.add_argument("--exit", type=int, default=0)
    parser.add_argument("--silent", action="store_true")
    args = parser.parse_args(argv[1:])

    if not args.silent:
        for index in range(1, args.lines + 1):
            print(f"{PROGRESS_PREFIX}step {index} of {args.lines}", file=sys.stderr, flush=True)
            if args.delay:
                time.sleep(args.delay)

    if args.stderr_bytes:
        noise = "x" * 200
        written = 0
        while written < args.stderr_bytes:
            print(noise, file=sys.stderr, flush=True)
            written += len(noise) + 1

    result = {
        "ok": args.exit == 0,
        "steps": [{"kind": "write", "detail": "/etc/sysctl.d/99-oss.conf", "ok": True, "output": ""}],
        "outcomes": {"kptr_restrict": "applied"},
        "error": "" if args.exit == 0 else "simulated failure",
        "rolled_back": False,
        "needs_reboot": [],
        "ufw": {},
        "apparmor": {},
        "integrity": {},
    }
    print(json.dumps(result))
    return args.exit


if __name__ == "__main__":
    sys.exit(main(sys.argv))
