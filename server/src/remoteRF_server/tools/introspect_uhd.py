"""Generate and verify the target-machine UHD Python API manifest.

Usage:
    python -m remoteRF_server.tools.introspect_uhd --output uhd-4.10.json

This does not open hardware. Hardware capability probes are performed when a
RemoteRF session opens the inventory-bound serial.
"""
from __future__ import annotations

import argparse
import inspect
import json
from pathlib import Path

from ..drivers.usrp.uhd_manifest import (
    MULTIUSRP_METHODS,
    TARGET_UHD_VERSION,
    build_usrp_schema_v2,
)


def _version(uhd, *names):
    for name in names:
        value = getattr(uhd, name, None)
        if callable(value):
            try:
                return str(value())
            except Exception:
                continue
        if value:
            return str(value)
    return ""


def _member_info(owner, name):
    value = getattr(owner, name, None)
    if value is None:
        return {"present": False}
    try:
        signature = str(inspect.signature(value))
    except (TypeError, ValueError):
        signature = ""
    return {
        "present": True,
        "signature": signature,
        "doc": inspect.getdoc(value) or "",
        "type": f"{type(value).__module__}.{type(value).__name__}",
    }


def generate_manifest():
    import uhd

    version = _version(uhd, "get_version_string", "get_version")
    abi = _version(uhd, "get_abi_string", "get_abi")
    owner = uhd.usrp.MultiUSRP
    members = {name: _member_info(owner, name) for name in MULTIUSRP_METHODS}
    public = sorted(name for name in dir(owner) if not name.startswith("_"))
    baseline = build_usrp_schema_v2()
    classified = {
        key.rsplit(".", 1)[-1]
        for key in baseline["coverage"]
        if key.startswith("uhd.usrp.MultiUSRP.")
    }
    return {
        "api_family": "uhd-python",
        "api_version": version,
        "abi": abi,
        "required_version": TARGET_UHD_VERSION,
        "members": members,
        "public_members": public,
        "unclassified_public_members": sorted(set(public) - classified),
        "missing_required_members": sorted(
            name for name, info in members.items()
            if not info["present"] and name not in {
                "get_radio_control", "get_mb_controller", "get_rx_radio_channel",
                "get_tx_radio_channel", "set_rx_spp", "set_tx_spp",
                "get_gpio_src", "set_gpio_src", "get_gpio_src_banks",
            }
        ),
        "deferred_schema_entries": sorted(
            key
            for key, value in baseline["coverage"].items()
            if value == "deferred"
        ),
        "schema_hash": baseline["schema_hash"],
    }


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--allow-version-mismatch",
        action="store_true",
        help="write diagnostics but do not fail solely for a UHD version mismatch",
    )
    args = parser.parse_args(argv)
    manifest = generate_manifest()
    args.output.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    failed = bool(
        manifest["missing_required_members"]
        or manifest["unclassified_public_members"]
        or manifest["deferred_schema_entries"]
    )
    if (
        not args.allow_version_mismatch
        and manifest["api_version"] != TARGET_UHD_VERSION
    ):
        failed = True
    if failed:
        print(json.dumps({
            "api_version": manifest["api_version"],
            "required_version": TARGET_UHD_VERSION,
            "missing_required_members": manifest["missing_required_members"],
            "unclassified_public_members": manifest["unclassified_public_members"],
            "deferred_schema_entries": manifest["deferred_schema_entries"],
        }, indent=2, sort_keys=True))
        return 2
    print(f"Wrote verified UHD manifest: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
