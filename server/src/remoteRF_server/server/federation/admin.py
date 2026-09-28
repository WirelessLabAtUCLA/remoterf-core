"""Headless Gate D trust and contract administration."""

from __future__ import annotations

import argparse
import base64
import hashlib
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from remoterf_federation_core import ContractError, canonical_json, strict_json

from . import identity
from .contracts import ContractStore
from .enrollment import ServerEnrollmentCodeStore
from .trust import TrustedKeyStore


def _json_file(path: str, *, maximum: int = 65536):
    return strict_json(Path(path).read_bytes(), max_bytes=maximum)


def _identity_values(args) -> tuple[str, object, str]:
    if args.identity_dir is None:
        raise ContractError("identity_dir_required")
    state_dir = Path(args.identity_dir)
    private_key = identity.load_private_key(state_dir)
    state = identity.load_state(state_dir)
    deployment_id = args.deployment_id or state.deployment_id
    if not deployment_id:
        raise ContractError("deployment_id_required")
    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    kid = args.kid or hashlib.sha256(raw).hexdigest()[:32]
    return deployment_id, private_key, kid


def _contract_store(args) -> ContractStore:
    deployment_id, private_key, kid = _identity_values(args)
    return ContractStore(
        args.db,
        local_deployment_id=deployment_id,
        private_key=private_key,
        signing_kid=kid,
    )


def _emit(value) -> None:
    print(canonical_json(value))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="remoterf-federation-admin",
        description="Local-only federation trust, contracts, and enrollment invitations.",
    )
    parser.add_argument("--db", required=True, help="Path to usergroups.db")
    parser.add_argument("--identity-dir", help="Deployment identity directory")
    parser.add_argument("--deployment-id", help="Canonical local deployment UUID")
    parser.add_argument("--kid", help="Local signing key ID (defaults to fingerprint prefix)")
    groups = parser.add_subparsers(dest="group", required=True)

    trust = groups.add_parser("trust")
    trust_commands = trust.add_subparsers(dest="command", required=True)
    trust_import = trust_commands.add_parser("import")
    trust_import.add_argument("--file", required=True)
    trust_import.add_argument("--approved-by", required=True)
    trust_import.add_argument(
        "--approval-source",
        required=True,
        choices=["manual_offline", "identity_file", "broker_candidate"],
    )
    trust_import.add_argument("--confirm-deployment-id", required=True)
    trust_import.add_argument("--confirm-kid", required=True)
    trust_import.add_argument("--confirm-fingerprint", required=True)
    trust_show = trust_commands.add_parser("show")
    trust_show.add_argument("--peer-deployment-id")
    trust_show.add_argument("--peer-kid")
    trust_revoke = trust_commands.add_parser("revoke")
    trust_revoke.add_argument("--peer-deployment-id", required=True)
    trust_revoke.add_argument("--peer-kid", required=True)
    trust_revoke.add_argument("--approved-by", required=True)
    identity_export = trust_commands.add_parser("export-identity")
    identity_export.add_argument("--valid-from", required=True, type=int)
    identity_export.add_argument("--valid-until", type=int)

    contract = groups.add_parser("contract")
    contract_commands = contract.add_subparsers(dest="command", required=True)
    propose = contract_commands.add_parser("propose")
    propose.add_argument("--terms-file", required=True)
    propose.add_argument("--admin-ref", required=True)
    show = contract_commands.add_parser("show")
    show.add_argument("--contract-id")
    show.add_argument("--version", type=int)
    export = contract_commands.add_parser("export")
    export.add_argument("--contract-id", required=True)
    export.add_argument("--version", required=True, type=int)
    export.add_argument("--output")
    import_command = contract_commands.add_parser("import")
    import_command.add_argument("--file", required=True)
    for name in ("accept", "activate", "suspend", "revoke"):
        command = contract_commands.add_parser(name)
        command.add_argument("--contract-id", required=True)
        command.add_argument("--version", required=True, type=int)
        command.add_argument("--admin-ref", required=True)
        if name in {"suspend", "revoke"}:
            command.add_argument("--reason-code")

    enrollment = groups.add_parser("enrollment")
    enrollment_commands = enrollment.add_subparsers(dest="command", required=True)
    create = enrollment_commands.add_parser("create")
    create.add_argument("--group-id", required=True, type=int)
    create.add_argument("--uses", required=True, type=int)
    create.add_argument("--duration", required=True, type=int)
    create.add_argument("--federation-contract", required=True)
    create.add_argument("--contract-version", required=True, type=int)
    create.add_argument("--allowed-issuer", required=True)
    return parser


def _run(args) -> None:
    if args.group == "enrollment":
        deployment_id, _, _ = _identity_values(args)
        invitation = ServerEnrollmentCodeStore(
            args.db, local_deployment_id=deployment_id
        ).create_federated(
            group_id=args.group_id,
            uses=args.uses,
            duration_sec=args.duration,
            contract_id=args.federation_contract,
            contract_version=args.contract_version,
            allowed_issuer_deployment_id=args.allowed_issuer,
        )
        print(invitation)
        return
    if args.group == "trust":
        if args.command == "export-identity":
            deployment_id, private_key, kid = _identity_values(args)
            raw = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            _emit(
                {
                    "deployment_id": deployment_id,
                    "kid": kid,
                    "public_key_b64": base64.b64encode(raw).decode("ascii"),
                    "public_key_sha256": hashlib.sha256(raw).hexdigest(),
                    "valid_from": args.valid_from,
                    "valid_until": args.valid_until,
                }
            )
            return
        store = TrustedKeyStore(args.db)
        if args.command == "import":
            _emit(
                store.import_key(
                    _json_file(args.file, maximum=4096),
                    approved_by=args.approved_by,
                    approval_source=args.approval_source,
                    confirm_deployment_id=args.confirm_deployment_id,
                    confirm_kid=args.confirm_kid,
                    confirm_fingerprint=args.confirm_fingerprint,
                )
            )
        elif args.command == "show":
            if args.peer_kid and not args.peer_deployment_id:
                raise ContractError("deployment_id_required")
            if args.peer_deployment_id and args.peer_kid:
                _emit(store.get(args.peer_deployment_id, args.peer_kid))
            else:
                _emit(store.list(args.peer_deployment_id))
        else:
            _emit(
                store.revoke(
                    args.peer_deployment_id,
                    args.peer_kid,
                    approved_by=args.approved_by,
                )
            )
        return

    store = _contract_store(args)
    if args.command == "propose":
        _emit(
            store.propose(
                _json_file(args.terms_file, maximum=4096),
                actor_admin_ref=args.admin_ref,
            )
        )
    elif args.command == "show":
        if args.contract_id is None and args.version is None:
            _emit(store.list())
        elif args.contract_id is None or args.version is None:
            raise ContractError("contract_id_and_version_required")
        else:
            _emit(store.show(args.contract_id, args.version))
    elif args.command == "export":
        value = store.export_bundle(args.contract_id, args.version)
        if args.output:
            Path(args.output).write_text(value + "\n", encoding="utf-8")
        else:
            print(value)
    elif args.command == "import":
        _emit(store.import_bundle(Path(args.file).read_bytes()))
    else:
        operation = getattr(store, args.command)
        kwargs = {"actor_admin_ref": args.admin_ref}
        if getattr(args, "reason_code", None):
            kwargs["reason_code"] = args.reason_code
        _emit(operation(args.contract_id, args.version, **kwargs))


def main(argv: list[str] | None = None) -> int:
    try:
        _run(_build_parser().parse_args(argv))
        return 0
    except (ValueError, OSError, identity.IdentityError) as exc:
        code = exc.code if isinstance(exc, ContractError) else type(exc).__name__
        print(f"error: {code}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
