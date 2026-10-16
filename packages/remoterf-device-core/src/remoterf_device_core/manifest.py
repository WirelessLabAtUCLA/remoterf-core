# Copyright (C) 2026 RemoteRF
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""The built-in drivers' schema hashes: schemas.json, built by `python -m remoterf_device_core.manifest`.

A lab trusts a host device's schema as its own copy only when the host reports
one of these hashes, and Global pre-approves them at each release.
"""
from __future__ import annotations

import functools
import importlib
import json
import sys
import types
from pathlib import Path

from .digest import schema_digest  # noqa: F401  (re-exported)

BUILTIN_MODULES = (
    "remoterf_device_core.drivers.adalm_pluto.pluto_schema",
    "remoterf_device_core.drivers.adalm_pluto.pluto_mimo_schema",
    "remoterf_device_core.drivers.hackrf.hackrf_schema",
    "remoterf_device_core.drivers.rtl_sdr.rtl_sdr_schema",
    "remoterf_device_core.drivers.ti_mmwave.ti_mmwave_schema",
    "remoterf_device_core.drivers.usrp.usrp_schema",
    "remoterf_device_core.drivers.usrp_phaser.usrp_phaser_schema",
)
MANIFEST_PATH = Path(__file__).with_name("schemas.json")


def build() -> list[dict]:
    """Import every built-in driver and list (type, version, v1 and v2 hashes)."""
    if "adi" not in sys.modules:
        try:
            import adi  # noqa: F401
        except Exception:
            # The interface does not touch pyadi; a machine without libiio still builds the manifest.
            sys.modules["adi"] = types.ModuleType("adi")
    from .idl.schema import DeviceSchema

    rows = []
    for name in BUILTIN_MODULES:
        module = importlib.import_module(name)
        for cls in vars(module).values():
            if not (isinstance(cls, type) and issubclass(cls, DeviceSchema) and cls.__module__ == name and cls.device_type):
                continue
            schema = cls()
            v2 = getattr(schema, "get_idl_v2", None)
            rows.append({
                "device_type": cls.device_type,
                "driver_version": cls.driver_version,
                "v1": schema.get_idl_hash(),
                "v2": v2()["schema_hash"] if callable(v2) else None,
            })
    return sorted(rows, key=lambda r: r["device_type"])


def load() -> list[dict]:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


@functools.lru_cache(maxsize=1)
def builtin_hashes() -> frozenset:
    return frozenset(h for row in load() for h in (row["v1"], row["v2"]) if h)


if __name__ == "__main__":
    MANIFEST_PATH.write_text(json.dumps(build(), indent=1) + "\n", encoding="utf-8")
    print(MANIFEST_PATH.read_text(encoding="utf-8"))
