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

"""The host's drivers config dir: managed copies of the built-in schemas, and loading it."""
from __future__ import annotations

import hashlib
import importlib
import re
import shutil
import sys
import types
from pathlib import Path
from typing import Dict

from . import schema as _schema
from ..utils import get_drivers_dir
from ..utils.host_logging import warn

# Every Pluto schema file a released hostrf copied here (copy-if-missing, never
# refreshed): an exact match is ours to upgrade; an edited copy is a custom driver.
_LEGACY_PLUTO_SCHEMA_HASHES = (
    "1260d687419c4bfe3e7dc60df58a55f5757b741898474e70f36c91603be70894",
    "48f351bda3485080849d797af853dfe2ce9652fded0bb04299b873315527cf63",
    "676dd91507842312c880ebd51733e9fedc4dff8fdece19902e4501e0256857e2",
    "75138b02e9d3dff830d7b1fda1778163a28e1c1e74c1ccbdeb91f7de46616fe8",
    "a3697eeef55827e0db7705685f8fe64b615468dd26057211de8b5805b9ecf583",
    "c165ab2596d8a3d1a7ef04f9be51264b0d375ae5585175c4a9badbfc0a7a3005",
    "d94bf5933c26f29516c2ddd159d43ba24b6c9e6a522bcfd9355cdb2e7e9b90ae",
    "e66c0dee2516a1c6a33dba0c5127d2c7a87d8536c9fb60fd71b22dce54b59789",
    "fc8e879e31fe4a2a0e94e2f12772aa7276c132f8209add1b77db69feab351c86",
)
_LEGACY_PLUTO_MIMO_SCHEMA_HASHES = (
    "4c342dcccf2af9cac5bfe97d1ec9ad2d14f499582131226aa4532abfb1519fcb",
    "64d47cafad51b782082595181370eb561ebd114cb4a64c55f5f2bfff195c23a6",
)


def _driver_registers_type(path: Path, device_type: str) -> bool:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return False
    pattern = rf"(?:idl_register|register_driver)\(\s*['\"]{re.escape(device_type)}['\"]\s*\)"
    return re.search(pattern, text) is not None


def _driver_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _driver_normalized_sha256(path: Path) -> str:
    text = path.read_text(encoding="utf-8").replace("\r\n", "\n")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _managed_driver_marker(target: Path) -> Path:
    return target.with_name(f".{target.name}.remoterf-managed")


def _seed_default_driver(
    filename: str,
    device_type: str,
    source: Path,
    *,
    legacy_hashes: tuple[str, ...] = (),
) -> None:
    """Install/refresh one packaged schema without replacing custom drivers."""
    drivers_dir = get_drivers_dir()
    drivers_dir.mkdir(parents=True, exist_ok=True)
    target = drivers_dir / filename

    if target.exists() or target.is_symlink():
        marker = _managed_driver_marker(target)
        try:
            target_hash = _driver_sha256(target)
            marker_hash = marker.read_text(encoding="utf-8").strip() if marker.exists() else ""
            normalized_hash = _driver_normalized_sha256(target)
            if (
                target_hash != marker_hash
                and normalized_hash != marker_hash
                and target_hash not in legacy_hashes
            ):
                return
            source_hash = _driver_sha256(source)
            if target_hash != source_hash:
                shutil.copy2(source, target)
            marker.write_text(source_hash + "\n", encoding="utf-8")
        except OSError as exc:
            warn(f"Could not refresh managed {device_type} schema: {exc}", component="hostrf.device_manager")
        return

    for driver_file in drivers_dir.glob("*.py"):
        if _driver_registers_type(driver_file, device_type):
            return

    if not source.is_file():
        warn(
            f"Packaged {device_type} schema is missing: {source}",
            component="hostrf.device_manager",
        )
        return

    try:
        shutil.copy2(source, target)
        _managed_driver_marker(target).write_text(
            _driver_sha256(source) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        warn(
            f"Could not install default {device_type} schema: {exc}",
            component="hostrf.device_manager",
        )


def _packaged_schema_path(driver_dir: str, filename: str) -> Path:
    import remoterf_device_core.drivers as core_drivers

    return Path(core_drivers.__file__).resolve().parent / driver_dir / filename


def ensure_default_driver_files() -> None:
    _seed_default_driver(
        "pluto_schema.py",
        "adalm_pluto",
        _packaged_schema_path("adalm_pluto", "pluto_schema.py"),
        legacy_hashes=_LEGACY_PLUTO_SCHEMA_HASHES,
    )
    _seed_default_driver(
        "pluto_mimo_schema.py",
        "adalm_pluto_mimo",
        _packaged_schema_path("adalm_pluto", "pluto_mimo_schema.py"),
        legacy_hashes=_LEGACY_PLUTO_MIMO_SCHEMA_HASHES,
    )


def install_server_import_compat() -> None:
    """
    Make server-authored schema imports resolve to the host IDL implementation.

    This lets host driver files reuse the exact same import lines as server
    driver files, e.g.:

        from remoteRF_server.common.idl import DeviceSchema, idl_register, idl_expose
    """
    schema_mod = _schema
    idl_pkg = sys.modules.get(__package__)
    if idl_pkg is None:
        return

    server_pkg_name = "remoteRF_server"
    common_pkg_name = "remoteRF_server.common"
    idl_pkg_name = "remoteRF_server.common.idl"
    schema_pkg_name = "remoteRF_server.common.idl.schema"

    server_pkg = sys.modules.get(server_pkg_name)
    if server_pkg is None:
        server_pkg = types.ModuleType(server_pkg_name)
        server_pkg.__path__ = []
        sys.modules[server_pkg_name] = server_pkg

    common_pkg = sys.modules.get(common_pkg_name)
    if common_pkg is None:
        common_pkg = types.ModuleType(common_pkg_name)
        common_pkg.__path__ = []
        sys.modules[common_pkg_name] = common_pkg

    sys.modules[idl_pkg_name] = idl_pkg
    sys.modules[schema_pkg_name] = schema_mod
    v2_mod = sys.modules.get("remoterf_device_core.idl.v2")
    if v2_mod is not None:
        sys.modules["remoteRF_server.common.idl.v2"] = v2_mod

    setattr(server_pkg, "common", common_pkg)
    setattr(common_pkg, "idl", idl_pkg)
    setattr(idl_pkg, "schema", schema_mod)

    # Server-authored USRP schema files are intentionally portable to HostRF.
    # Alias their pinned, hardware-independent manifest to the host package so
    # a shared ~/.config/remoterf/drivers directory works in either process.
    try:
        host_drivers = importlib.import_module("remoteRF_host.drivers")
        host_usrp = importlib.import_module("remoteRF_host.drivers.usrp")
        host_manifest = importlib.import_module(
            "remoteRF_host.drivers.usrp.uhd_manifest"
        )
        host_profiles = importlib.import_module(
            "remoteRF_host.drivers.usrp.profiles"
        )
    except Exception:
        pass
    else:
        sys.modules["remoteRF_server.drivers"] = host_drivers
        sys.modules["remoteRF_server.drivers.usrp"] = host_usrp
        sys.modules["remoteRF_server.drivers.usrp.uhd_manifest"] = host_manifest
        sys.modules["remoteRF_server.drivers.usrp.profiles"] = host_profiles
        setattr(server_pkg, "drivers", host_drivers)
        setattr(host_drivers, "usrp", host_usrp)
        setattr(host_usrp, "uhd_manifest", host_manifest)
        setattr(host_usrp, "profiles", host_profiles)


def load_drivers() -> Dict[str, str]:
    install_server_import_compat()
    ensure_default_driver_files()
    return _schema.load_drivers()
