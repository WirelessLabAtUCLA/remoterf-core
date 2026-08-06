"""Structured USRP hardware profiles and live profile resolution.

Profiles describe how RemoteRF selects a device and how it should be reported.
They do not replace UHD capability queries: frequency, gain, channel, sensor,
and stream-format support always come from the connected device at runtime.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping


QUALIFIED_NATIVE = "qualified_native"
GENERIC_UHD = "generic_uhd"


@dataclass(frozen=True)
class USRPProfile:
    """Declarative description of one qualified model or UHD family."""

    profile_id: str
    display_name: str
    family: str
    transport: str
    support_level: str
    selector: str
    uhd_device_type: str
    aliases: tuple[str, ...] = ()
    identity_terms: tuple[str, ...] = ()
    qualified_models: tuple[str, ...] = ()
    default_link_rate_bps: int | None = None
    notes: str = ""

    @property
    def is_qualified(self) -> bool:
        return self.support_level == QUALIFIED_NATIVE

    def matches_identity(self, values: Iterable[Any]) -> bool:
        identity = " ".join(str(value or "").lower() for value in values)
        return any(term.lower() in identity for term in self.identity_terms)

    def public_definition(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "display_name": self.display_name,
            "family": self.family,
            "transport": self.transport,
            "support_level": self.support_level,
            "selector": self.selector,
            "uhd_device_type": self.uhd_device_type,
            "aliases": list(self.aliases),
            "identity_terms": list(self.identity_terms),
            "qualified_models": list(self.qualified_models),
            "default_link_rate_bps": self.default_link_rate_bps,
            "notes": self.notes,
        }


# Put exact, hardware-qualified profiles before family profiles. Adding a new
# USRP normally means adding one entry here and its read-only qualification
# test; the shared MultiUSRP implementation does not need another driver.
USRP_PROFILES: tuple[USRPProfile, ...] = (
    USRPProfile(
        profile_id="usrp2901",
        display_name="NI USRP-2901",
        family="b2xx",
        transport="usb",
        support_level=QUALIFIED_NATIVE,
        selector="serial",
        uhd_device_type="b200",
        aliases=("usrp-2901", "ni2901"),
        identity_terms=("ni2901", "usrp-2901", "usrp 2901"),
        qualified_models=("NI USRP-2901",),
        notes="Qualified against the native UHD B210-compatible implementation.",
    ),
    USRPProfile(
        profile_id="b205mini",
        display_name="Ettus Research USRP B205-mini",
        family="b2xx",
        transport="usb",
        support_level=QUALIFIED_NATIVE,
        selector="serial",
        uhd_device_type="b200",
        aliases=(
            "b205-mini",
            "usrp-b205-mini",
            "b205mini-i",
            "b205i",
        ),
        identity_terms=("b205mini", "b205-mini", "b205i"),
        qualified_models=("USRP B205-mini", "USRP B205mini-i"),
        notes=(
            "Qualified as the single-channel B2xx-mini implementation over "
            "USB 3 with the native UHD driver."
        ),
    ),
    USRPProfile(
        profile_id="n210",
        display_name="USRP N210",
        family="n2xx",
        transport="ethernet",
        support_level=QUALIFIED_NATIVE,
        selector="address",
        uhd_device_type="usrp2",
        aliases=("usrp-n210",),
        identity_terms=("n210",),
        qualified_models=("USRP N210",),
        default_link_rate_bps=1_000_000_000,
        notes="Qualified over the UHD USRP2 Gigabit Ethernet transport.",
    ),
    USRPProfile(
        profile_id="b2xx",
        display_name="Generic USRP B2xx family",
        family="b2xx",
        transport="usb",
        support_level=GENERIC_UHD,
        selector="serial",
        uhd_device_type="b200",
        aliases=("b200", "b210", "b200mini"),
        identity_terms=("b200", "b210", "b200mini"),
        notes="Uses the shared UHD API but requires model-specific qualification.",
    ),
    USRPProfile(
        profile_id="n2xx",
        display_name="Generic USRP N2xx family",
        family="n2xx",
        transport="ethernet",
        support_level=GENERIC_UHD,
        selector="address",
        uhd_device_type="usrp2",
        aliases=("usrp2", "n200"),
        identity_terms=("n200", "n210"),
        default_link_rate_bps=1_000_000_000,
        notes="Uses the shared UHD API but requires model-specific qualification.",
    ),
    USRPProfile(
        profile_id="x3xx",
        display_name="Generic USRP X3xx family",
        family="x3xx",
        transport="ethernet",
        support_level=GENERIC_UHD,
        selector="address",
        uhd_device_type="x300",
        aliases=("x300", "x310"),
        identity_terms=("x300", "x310"),
        notes="Generic UHD control/streaming support; hardware is not yet qualified.",
    ),
    USRPProfile(
        profile_id="n3xx",
        display_name="Generic USRP N3xx family",
        family="n3xx",
        transport="ethernet",
        support_level=GENERIC_UHD,
        selector="address",
        uhd_device_type="n3xx",
        aliases=("n300", "n310", "n320", "n321"),
        identity_terms=("n300", "n310", "n320", "n321"),
        notes="Generic UHD control/streaming support; hardware is not yet qualified.",
    ),
    USRPProfile(
        profile_id="x4xx",
        display_name="Generic USRP X4xx family",
        family="x4xx",
        transport="ethernet",
        support_level=GENERIC_UHD,
        selector="address",
        uhd_device_type="x4xx",
        aliases=("x410", "x440"),
        identity_terms=("x410", "x440"),
        notes="Generic UHD control/streaming support; hardware is not yet qualified.",
    ),
    USRPProfile(
        profile_id="e3xx",
        display_name="Generic USRP E3xx family",
        family="e3xx",
        transport="embedded",
        support_level=GENERIC_UHD,
        selector="device_args",
        uhd_device_type="e3xx",
        aliases=("e310", "e320"),
        identity_terms=("e310", "e320"),
        notes="Generic UHD support for server software running on/near the device.",
    ),
    USRPProfile(
        profile_id="generic_usrp",
        display_name="Generic UHD USRP",
        family="unknown",
        transport="runtime_detected",
        support_level=GENERIC_UHD,
        selector="device_args",
        uhd_device_type="",
        aliases=("generic",),
        notes="Fallback profile; all effective capabilities are runtime-reported.",
    ),
)


_PROFILE_NAMES: dict[str, USRPProfile] = {}
for _profile in USRP_PROFILES:
    for _name in (_profile.profile_id, *_profile.aliases):
        _key = _name.strip().lower()
        if _key in _PROFILE_NAMES:
            raise RuntimeError(f"duplicate USRP profile name: {_name}")
        _PROFILE_NAMES[_key] = _profile


def get_usrp_profile(name: str) -> USRPProfile:
    try:
        return _PROFILE_NAMES[str(name or "").strip().lower()]
    except KeyError as exc:
        supported = ", ".join(profile.profile_id for profile in USRP_PROFILES)
        raise ValueError(
            f"unknown USRP profile {name!r}; expected one of: {supported}"
        ) from exc


def profile_definitions() -> list[dict[str, Any]]:
    return [profile.public_definition() for profile in USRP_PROFILES]


def advertised_profile_names() -> list[str]:
    """Return canonical profile IDs plus accepted compatibility aliases."""
    return list(_PROFILE_NAMES)


def infer_inventory_profile(inventory: Mapping[str, Any]) -> USRPProfile:
    requested = str(inventory.get("profile") or "").strip()
    if requested:
        return get_usrp_profile(requested)

    # Preserve old RemoteRF inventories: --usrp meant a 2901 and an address-
    # bound USRP2 entry meant the then-only network profile, N210. New family
    # inventories always include an explicit profile and bypass this branch.
    if inventory.get("addr") and str(
        inventory.get("type") or inventory.get("device_type") or ""
    ).strip().lower() in {"", "usrp2"}:
        return get_usrp_profile("n210")
    if inventory.get("serial") and str(
        inventory.get("type") or inventory.get("device_type") or ""
    ).strip().lower() in {"", "b200"}:
        return get_usrp_profile("usrp2901")

    device_type = str(
        inventory.get("type") or inventory.get("device_type") or ""
    ).strip().lower()
    if device_type:
        matches = [
            profile
            for profile in USRP_PROFILES
            if profile.uhd_device_type == device_type
        ]
        if len(matches) == 1:
            return matches[0]
        if device_type == "usrp2":
            return get_usrp_profile("n2xx")
        if device_type == "b200":
            return get_usrp_profile("b2xx")

    return get_usrp_profile("generic_usrp")


def validate_profile_inventory(
    profile: USRPProfile,
    inventory: Mapping[str, Any],
) -> None:
    """Reject configuration that contradicts an explicitly selected profile."""
    configured_type = str(
        inventory.get("type") or inventory.get("device_type") or ""
    ).strip().lower()
    if not configured_type and isinstance(inventory.get("args"), str):
        for item in str(inventory["args"]).split(","):
            key, separator, value = item.partition("=")
            if separator and key.strip().lower() == "type":
                configured_type = value.strip().lower()
                break
    if (
        configured_type
        and profile.uhd_device_type
        and configured_type != profile.uhd_device_type
    ):
        raise ValueError(
            f"USRP profile {profile.profile_id!r} requires UHD type "
            f"{profile.uhd_device_type!r}, not {configured_type!r}"
        )

    selector_values = {
        "serial": inventory.get("serial"),
        "address": inventory.get("addr"),
        "device_args": inventory.get("args"),
    }
    supplied = {
        key for key, value in selector_values.items() if str(value or "").strip()
    }
    if profile.selector not in supplied:
        provided = ", ".join(sorted(supplied)) or "no selector"
        raise ValueError(
            f"USRP profile {profile.profile_id!r} requires selector "
            f"{profile.selector!r}, not {provided}"
        )


def resolve_live_profile(
    inventory: Mapping[str, Any],
    *identity_values: Any,
) -> tuple[USRPProfile, dict[str, Any]]:
    """Resolve the live model, preferring native identity over configuration."""
    requested = infer_inventory_profile(inventory)
    identity_present = any(str(value or "").strip() for value in identity_values)
    detected = next(
        (
            profile
            for profile in USRP_PROFILES
            if profile.identity_terms and profile.matches_identity(identity_values)
        ),
        None,
    )
    profile = detected or requested
    if profile.profile_id == "generic_usrp" and identity_present:
        source = "generic_fallback"
    elif detected is not None:
        source = "native_identity"
    elif inventory:
        source = "inventory"
    else:
        source = "generic_fallback"
    return profile, {
        "source": source,
        "requested_profile": requested.profile_id,
        "resolved_profile": profile.profile_id,
        "requested_profile_matches": requested.profile_id == profile.profile_id,
    }


def inventory_for_profile(profile_name: str, selector: str) -> dict[str, str]:
    """Build canonical server inventory for a profile and device selector."""
    profile = get_usrp_profile(profile_name)
    value = str(selector or "").strip()
    if not value:
        raise ValueError(f"{profile.selector} is empty")
    inventory = {"profile": profile.profile_id}
    if profile.uhd_device_type:
        inventory["type"] = profile.uhd_device_type
    if profile.selector == "serial":
        inventory["serial"] = value
    elif profile.selector == "address":
        inventory["addr"] = value
    elif profile.selector == "device_args":
        inventory["args"] = value
    else:
        raise ValueError(f"unsupported selector type: {profile.selector}")
    return inventory
