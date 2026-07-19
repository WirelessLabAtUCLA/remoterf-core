"""Server-owned USRP policy enforcement.

Missing, unreadable, or incomplete policy files intentionally deny TX and
low-level writes.  Read-only control and RX remain available.
"""
from __future__ import annotations

import os
import time
from collections import deque
from pathlib import Path
from typing import Any, Mapping

from ...server.v2_errors import RemoteRFPolicyError

try:
    import yaml
except ImportError:  # pragma: no cover - deployment dependency, deny-safe fallback
    yaml = None


def default_policy_path() -> Path:
    root = Path(
        os.getenv(
            "REMOTERF_CONFIG_DIR",
            Path(os.getenv("XDG_CONFIG_HOME", Path.home() / ".config")) / "remoterf",
        )
    )
    return root / "usrp_policy.yml"


def _inside_ranges(value: float, ranges) -> bool:
    for entry in ranges or ():
        try:
            low, high = float(entry[0]), float(entry[1])
        except (TypeError, ValueError, IndexError):
            continue
        if low <= float(value) <= high:
            return True
    return False


def _argument(args: Mapping[str, Any], *names: str, position: int | None = None):
    for name in names:
        if name in args:
            return args[name]
    positional = args.get("__args__", ())
    if position is not None and isinstance(positional, (list, tuple)):
        if 0 <= position < len(positional):
            return positional[position]
    return None


class USRPPolicy:
    def __init__(self, config: Mapping[str, Any] | None = None, *, source: str = ""):
        self.config = dict(config or {})
        self.source = source
        self._tx_history: deque[tuple[float, float]] = deque()

    @classmethod
    def load(cls, *, gid: int, serial: str = "", path: Path | None = None) -> "USRPPolicy":
        path = path or default_policy_path()
        if yaml is None or not path.exists():
            return cls({}, source=str(path))
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            if not isinstance(raw, Mapping):
                raise TypeError("policy root must be a mapping")
            defaults = dict(raw.get("defaults") or {})
            devices = dict(raw.get("devices") or {})
            selected = devices.get(str(gid)) or devices.get(serial) or {}
            merged = dict(defaults)
            merged.update(dict(selected or {}))
        except Exception:
            return cls({}, source=str(path))
        return cls(merged, source=str(path))

    @property
    def tx_enabled(self) -> bool:
        return self.config.get("tx_enabled") is True

    @property
    def restrictions(self) -> dict[str, Any]:
        return {
            "tx_enabled": self.tx_enabled,
            "tx_frequency_ranges_hz": self.config.get("tx_frequency_ranges_hz", []),
            "max_tx_gain_db": self.config.get("max_tx_gain_db"),
            "max_tx_power_dbm": self.config.get("max_tx_power_dbm"),
            "max_tx_bandwidth_hz": self.config.get("max_tx_bandwidth_hz"),
            "max_tx_sample_rate_sps": self.config.get("max_tx_sample_rate_sps"),
            "allowed_tx_antennas": self.config.get("allowed_tx_antennas", []),
            "max_burst_seconds": self.config.get("max_burst_seconds"),
            "max_duty_cycle": self.config.get("max_duty_cycle"),
            "low_level_write_enabled": self.config.get("low_level_write_enabled") is True,
            "low_level_write_methods": self.config.get("low_level_write_methods", []),
        }

    def _require_tx(self) -> None:
        if not self.tx_enabled:
            raise RemoteRFPolicyError(
                "USRP transmit is disabled until an administrator configures usrp_policy.yml",
                details={"policy_source": self.source},
            )

    def check_control(self, method: str, args: Mapping[str, Any]) -> None:
        if method.startswith("set_tx_") or method == "send_waveform":
            self._require_tx()

        if method in {"set_tx_freq", "set_tx_lo_freq", "send_waveform"}:
            value = _argument(
                args,
                "tune_request",
                "freq",
                "frequency",
                position=0,
            )
            if isinstance(value, Mapping):
                value = value.get("target_freq", value.get("freq"))
            ranges = self.config.get("tx_frequency_ranges_hz") or []
            if value is None or not ranges or not _inside_ranges(float(value), ranges):
                raise RemoteRFPolicyError(
                    f"TX frequency is outside the configured policy ranges",
                    details={"method": method, "requested_hz": value, "allowed_ranges_hz": ranges},
                    method=method,
                )

        if method == "set_tx_gain":
            limit = self.config.get("max_tx_gain_db")
            value = _argument(args, "gain", position=0)
            if limit is None or value is None or float(value) > float(limit):
                raise RemoteRFPolicyError(
                    "TX gain exceeds or lacks an administrator limit",
                    details={"requested_db": value, "maximum_db": limit},
                    method=method,
                )

        if method == "set_tx_normalized_gain":
            limit = self.config.get("max_tx_normalized_gain")
            value = _argument(args, "gain", position=0)
            if limit is None or value is None or float(value) > float(limit):
                raise RemoteRFPolicyError(
                    "normalized TX gain exceeds or lacks an administrator limit",
                    details={"requested": value, "maximum": limit},
                    method=method,
                )

        if method == "set_tx_power_reference":
            limit = self.config.get("max_tx_power_dbm")
            value = _argument(args, "power_dbm", "power", position=0)
            if limit is None or value is None or float(value) > float(limit):
                raise RemoteRFPolicyError(
                    "TX power reference exceeds or lacks an administrator limit",
                    details={"requested_dbm": value, "maximum_dbm": limit},
                    method=method,
                )

        if method == "set_tx_bandwidth":
            limit = self.config.get("max_tx_bandwidth_hz")
            value = _argument(args, "bandwidth", position=0)
            if limit is None or value is None or float(value) > float(limit):
                raise RemoteRFPolicyError(
                    "TX bandwidth exceeds or lacks an administrator limit",
                    details={"requested_hz": value, "maximum_hz": limit},
                    method=method,
                )

        if method == "set_tx_rate":
            limit = self.config.get("max_tx_sample_rate_sps")
            value = _argument(args, "rate", position=0)
            if limit is None or value is None or float(value) > float(limit):
                raise RemoteRFPolicyError(
                    "TX sample rate exceeds or lacks an administrator limit",
                    details={"requested_sps": value, "maximum_sps": limit},
                    method=method,
                )

        if method == "set_tx_antenna":
            allowed = {
                str(value)
                for value in (self.config.get("allowed_tx_antennas") or ())
            }
            antenna = str(_argument(args, "antenna", position=0) or "")
            if not allowed or antenna not in allowed:
                raise RemoteRFPolicyError(
                    "TX antenna is not in the administrator allowlist",
                    details={"requested": antenna, "allowed": sorted(allowed)},
                    method=method,
                )

        if method == "set_tx_lo_source":
            allowed = {
                str(value)
                for value in (self.config.get("allowed_tx_lo_sources") or ())
            }
            source = str(_argument(args, "source", position=0) or "")
            if not allowed or source not in allowed:
                raise RemoteRFPolicyError(
                    "TX LO source is not in the administrator allowlist",
                    details={"requested": source, "allowed": sorted(allowed)},
                    method=method,
                )

        if (
            method == "set_tx_lo_export_enabled"
            and bool(_argument(args, "enabled", "enable", position=0))
            and self.config.get("allow_tx_lo_export") is not True
        ):
            raise RemoteRFPolicyError(
                "TX LO export is disabled by administrator policy",
                method=method,
            )

        if (
            method == "set_rx_lo_export_enabled"
            and bool(_argument(args, "enabled", "enable", position=0))
            and self.config.get("allow_rx_lo_export") is not True
        ):
            raise RemoteRFPolicyError(
                "RX LO export is disabled by administrator policy",
                method=method,
            )

        if method == "send_waveform":
            self.check_control(
                "set_tx_rate",
                {"rate": _argument(args, "rate", position=3)},
            )
            self.check_control(
                "set_tx_gain",
                {"gain": _argument(args, "gain", position=5)},
            )
            self.check_tx_duration(
                float(_argument(args, "duration", position=1) or 0.0)
            )

        if method in {
            "set_gpio_attr", "set_gpio_src", "set_user_register",
            "set_rx_filter", "set_tx_filter",
        }:
            self._check_low_level_write("", method, args)

    def check_tx_duration(self, duration: float) -> None:
        self._require_tx()
        if duration < 0:
            raise RemoteRFPolicyError("TX duration cannot be negative")
        maximum = self.config.get("max_burst_seconds")
        try:
            maximum_value = float(maximum)
        except (TypeError, ValueError):
            maximum_value = -1.0
        if maximum_value < 0 or duration > maximum_value:
            raise RemoteRFPolicyError(
                "TX duration exceeds or lacks an administrator limit",
                details={"requested_seconds": duration, "maximum_seconds": maximum},
            )

        try:
            window = float(self.config.get("duty_cycle_window_seconds", 60.0))
        except (TypeError, ValueError):
            window = 0.0
        fraction = self.config.get("max_duty_cycle")
        try:
            fraction_value = float(fraction)
        except (TypeError, ValueError):
            fraction_value = -1.0
        if window <= 0 or not 0 <= fraction_value <= 1:
            raise RemoteRFPolicyError("TX duty-cycle policy is not configured")
        now = time.monotonic()
        while self._tx_history and self._tx_history[0][0] < now - window:
            self._tx_history.popleft()
        used = sum(item[1] for item in self._tx_history)
        if used + duration > window * fraction_value:
            raise RemoteRFPolicyError(
                "TX duty-cycle limit would be exceeded",
                details={"window_seconds": window, "maximum_fraction": fraction},
            )
        self._tx_history.append((now, duration))

    def check_handle_call(self, type_id: str, method: str, args: Mapping[str, Any]) -> None:
        """Keep returned low-level interfaces read-only unless allowlisted."""
        read_prefixes = ("get", "read", "list", "exists", "to_", "peek")
        if method.startswith(read_prefixes) or method in {"access", "subtree"}:
            return
        self._check_low_level_write(type_id, method, args)

    def _check_low_level_write(
        self,
        type_id: str,
        method: str,
        args: Mapping[str, Any],
    ) -> None:
        allowed = set(self.config.get("low_level_write_methods") or ())
        if self.config.get("low_level_write_enabled") is not True or method not in allowed:
            raise RemoteRFPolicyError(
                f"{type_id}.{method} is not allowlisted for low-level writes",
                details={"type_id": type_id, "method": method},
                method=method,
            )

        if method == "set_gpio_attr":
            bank = str(args.get("bank", ""))
            requested_mask = int(_argument(args, "mask", position=3) or 0)
            allowed_mask = int(
                dict(self.config.get("gpio_write_masks") or {}).get(bank, 0)
            )
            if requested_mask & ~allowed_mask:
                raise RemoteRFPolicyError(
                    "GPIO write mask exceeds the administrator allowlist",
                    details={
                        "bank": bank,
                        "requested_mask": requested_mask,
                        "allowed_mask": allowed_mask,
                    },
                    method=method,
                )

        path_value = _argument(
            args,
            "path",
            "property_path",
            "key",
            position=0,
        )
        path = str(path_value) if path_value is not None else ""
        if path:
            allowed_paths = tuple(
                str(value)
                for value in (self.config.get("property_write_paths") or ())
            )
            if not allowed_paths or not any(
                path == prefix or path.startswith(prefix.rstrip("/") + "/")
                for prefix in allowed_paths
            ):
                raise RemoteRFPolicyError(
                    "property-tree write path is not allowlisted",
                    details={"path": path, "allowed_paths": list(allowed_paths)},
                    method=method,
                )

        if method in {"poke32", "poke64", "write_register", "set_user_register"}:
            address = _argument(args, "addr", "address", position=0)
            allowed_addresses = {
                int(value, 0) if isinstance(value, str) else int(value)
                for value in (self.config.get("register_write_addresses") or ())
            }
            if address is None or int(address) not in allowed_addresses:
                raise RemoteRFPolicyError(
                    "register write address is not allowlisted",
                    details={
                        "address": address,
                        "allowed_addresses": sorted(allowed_addresses),
                    },
                    method=method,
                )
