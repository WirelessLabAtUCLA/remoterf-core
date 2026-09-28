#!/usr/bin/env python3
"""Offline Gate C preflight/apply entry point; never runs during Server startup."""

import argparse
import json

from remoteRF_server.server.federation.legacy_state import (
    apply_disposal,
    write_preflight,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    preflight = commands.add_parser("preflight")
    preflight.add_argument("--db-dir", required=True)
    preflight.add_argument("--manifest", required=True)
    apply = commands.add_parser("apply")
    apply.add_argument("--manifest", required=True)
    apply.add_argument("--archive-dir", required=True)
    apply.add_argument("--deployment-id", required=True)
    args = parser.parse_args()
    if args.command == "preflight":
        result = write_preflight(args.db_dir, args.manifest)
    else:
        result = apply_disposal(
            args.manifest,
            archive_dir=args.archive_dir,
            deployment_id=args.deployment_id,
        )
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
