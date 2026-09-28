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

"""HOME side of the Server-to-Server device plane.

A partner's device appears to the Client as one more local device id, and a
reservation on it yields an ordinary HOME-minted token, so the native Client
protocol is untouched.  Underneath, every listing, reservation, cancel and
device RPC is one Gate H grant to the owner, which re-derives the decision
from its own tables; the rows kept here only route a token back to the owner.
A user reaches an owner only after enrolling there (`rrf2.` invitation).
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import datetime
from pathlib import Path

from remoterf_federation_core import (
    DEVICE_AGGREGATION_TIMEOUT_SECONDS,
    DEVICE_READ_TIMEOUT_SECONDS,
    MAX_DEVICE_ACTION_REQUEST_BYTES,
    MAX_DEVICE_RESULT_BYTES,
    FederationError,
    OwnerSignedFailure,
    TransportFailure,
    build_device_payload,
    canonical_uuid,
    decode_device_b64,
    encode_device_b64,
)

from ...common.grpc import grpc_pb2
from ...common.utils import generate_token, validate_token
from .migrations import configure_connection, migrate_home_devices_reservations_schema

logger = logging.getLogger(__name__)

# ponytail: aliases start above any plausible local/host device id; a real
# collision check against the live inventory can replace the constant.
ALIAS_BASE = 1_000_000


class HomeDeviceError(RuntimeError):
    """A refusal the ACC surface reports verbatim as an `ace` message."""


def _failure_text(exc: BaseException) -> str:
    if isinstance(exc, OwnerSignedFailure):
        return f"Partner refused: {exc.result['error_code']}"
    if isinstance(exc, TransportFailure):
        return f"Partner unreachable: {exc.code}"
    if isinstance(exc, FederationError):
        return f"Federation error: {exc.code}"
    return "Partner unreachable"


class ServerHomeDevices:
    def __init__(
        self,
        *,
        reservations_path,
        permissions,
        outbound,
        clock=None,
        max_concurrency: int = 4,
        per_destination_timeout: float = DEVICE_READ_TIMEOUT_SECONDS,
        overall_timeout: float = DEVICE_AGGREGATION_TIMEOUT_SECONDS,
    ):
        self.path = Path(reservations_path)
        self.permissions = permissions  # ServerHomePermissions: active-contract lookup
        self.outbound = outbound
        self.clock = clock or (lambda: int(time.time()))
        self.per_destination_timeout = float(per_destination_timeout)
        self.overall_timeout = float(overall_timeout)
        self._pool = ThreadPoolExecutor(
            max_workers=int(max_concurrency), thread_name_prefix="remoterf-home-devices"
        )
        self._write_lock = threading.Lock()
        with self._connect() as conn:
            migrate_home_devices_reservations_schema(conn)

    def close(self):
        self._pool.shutdown(wait=False, cancel_futures=True)

    def _connect(self):
        conn = sqlite3.connect(self.path, timeout=10.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        configure_connection(conn)
        return conn

    # -- enrollment / eligibility --------------------------------------

    def record_enrollment(self, *, local_account_id: int, destination_deployment_id: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO FederatedEnrollments "
                "(local_account_id,destination_deployment_id,enrolled_at) VALUES (?,?,?)",
                (int(local_account_id), canonical_uuid(destination_deployment_id), int(self.clock())),
            )

    def enrolled(self, local_account_id: int) -> set[str]:
        with self._connect() as conn:
            return self._enrolled_at(conn, local_account_id)

    def _enrolled_at(self, conn, local_account_id: int) -> set[str]:
        rows = conn.execute(
            "SELECT destination_deployment_id FROM FederatedEnrollments WHERE local_account_id=?",
            (int(local_account_id),),
        ).fetchall()
        return {row[0] for row in rows}

    def _candidates(self, local_account_id: int, capability: str) -> list[dict]:
        """One active contract per owner the account is enrolled at."""

        with self._connect() as conn:
            enrolled = self._enrolled_at(conn, local_account_id)
        if not enrolled:
            return []
        chosen = {}
        for candidate in self.permissions._candidates(int(self.clock()), capability)[0]:
            if candidate["deployment_id"] in enrolled:
                chosen.setdefault(candidate["deployment_id"], candidate)
        return [chosen[peer] for peer in sorted(chosen)]

    def _destination(self, local_account_id: int, owner: str, capability: str) -> dict:
        for candidate in self._candidates(local_account_id, capability):
            if candidate["deployment_id"] == owner:
                return candidate
        raise HomeDeviceError("You are not enrolled at the deployment that owns this device.")

    # -- one forwarded action ------------------------------------------

    def _forward(self, local_account_id, candidate, action, deadline=None, **payload):
        return self.outbound.execute(
            local_account_id=int(local_account_id),
            destination_deployment_id=candidate["deployment_id"],
            contract_id=candidate["contract_id"],
            contract_version=candidate["contract_version"],
            action=action,
            device_payload=build_device_payload(action=action, **payload),
            **({"deadline": deadline} if deadline is not None else {}),
        )

    def _fan_out(self, local_account_id: int, action: str) -> list[tuple[dict, dict]]:
        """(owner result, payload) for every reachable owner; unreachable ones are logged."""

        candidates = self._candidates(local_account_id, "DEVICE_READ")
        deadline = time.monotonic() + self.overall_timeout
        futures = {
            self._pool.submit(
                self._forward, local_account_id, candidate, action,
                min(deadline, time.monotonic() + self.per_destination_timeout),
            ): candidate
            for candidate in candidates
        }
        results = []
        pending = set(futures)
        while pending:
            done, pending = wait(
                pending, timeout=max(0.0, deadline - time.monotonic()), return_when=FIRST_COMPLETED
            )
            for future in done:
                try:
                    result = future.result()
                except Exception as exc:  # noqa: BLE001 - provenance goes to the log
                    logger.warning(
                        "home_devices_owner_unavailable owner=%s action=%s reason=%s",
                        futures[future]["deployment_id"], action, _failure_text(exc),
                    )
                    continue
                results.append((result, result["payload"]))
            if time.monotonic() >= deadline:
                break
        for future in pending:
            future.cancel()
            logger.warning(
                "home_devices_owner_unavailable owner=%s action=%s reason=timeout",
                futures[future]["deployment_id"], action,
            )
        results.sort(key=lambda item: item[0]["deployment_id"])
        return results

    # -- aliases ---------------------------------------------------------

    def _alias_locked(self, conn, owner: str, remote_device_id: str, display_name: str) -> int:
        row = conn.execute(
            "SELECT alias_id FROM FederatedDeviceAliases WHERE owner_deployment_id=? AND remote_device_id=?",
            (owner, str(remote_device_id)),
        ).fetchone()
        if row is not None:
            conn.execute(
                "UPDATE FederatedDeviceAliases SET display_name=? WHERE alias_id=?",
                (display_name, int(row[0])),
            )
            return int(row[0])
        alias = conn.execute(
            "SELECT COALESCE(MAX(alias_id), ?) + 1 FROM FederatedDeviceAliases", (ALIAS_BASE - 1,)
        ).fetchone()[0]
        conn.execute(
            "INSERT INTO FederatedDeviceAliases (alias_id,owner_deployment_id,remote_device_id,display_name) "
            "VALUES (?,?,?,?)",
            (int(alias), owner, str(remote_device_id), display_name),
        )
        return int(alias)

    def alias(self, device_id) -> sqlite3.Row | None:
        try:
            device_id = int(device_id)
        except (TypeError, ValueError):
            return None
        if device_id < ALIAS_BASE:
            return None
        with self._connect() as conn:
            return conn.execute(
                "SELECT alias_id,owner_deployment_id,remote_device_id,display_name "
                "FROM FederatedDeviceAliases WHERE alias_id=?",
                (device_id,),
            ).fetchone()

    # -- ACC surface -----------------------------------------------------

    def list_devices(self, *, local_account_id: int) -> dict[str, str]:
        """{alias id: label} in the shape of get_all_devices_str()."""

        out = {}
        entries = self._fan_out(local_account_id, "device_list")
        if not entries:
            return out
        with self._write_lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            for result, payload in entries:
                owner = result["deployment_id"]
                for device in payload.get("devices", []):
                    alias = self._alias_locked(
                        conn, owner, device["local_device_id"], str(device["display_name"])
                    )
                    status = "online" if device["online"] else "offline"
                    out[str(alias)] = f"{device['display_name']} @{result['display_name']} ({status})"
            conn.commit()
        return out

    def list_reservations(self, *, local_account_id: int, username: str) -> dict[str, str]:
        """Rows in the shape of grab_all_reservations(); own rows keyed by the HOME res_id."""

        out = {}
        entries = self._fan_out(local_account_id, "device_reservations")
        if not entries:
            return out
        with self._write_lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._purge_expired_locked(conn)
            for result, payload in entries:
                owner = result["deployment_id"]
                for row in payload.get("reservations", []):
                    alias = self._alias_locked(
                        conn, owner, row["local_device_id"], f"device {row['local_device_id']}"
                    )
                    key = f"{owner[:8]}:{row['reservation_id']}"
                    label = "reserved"
                    if row["mine"]:
                        label = username
                        local = conn.execute(
                            "SELECT res_id FROM HomeFederatedReservations "
                            "WHERE owner_deployment_id=? AND remote_reservation_id=?",
                            (owner, str(row["reservation_id"])),
                        ).fetchone()
                        if local is not None:
                            key = str(int(local[0]))
                    start = datetime.fromtimestamp(int(row["start_time"]))
                    end = datetime.fromtimestamp(int(row["end_time"]))
                    out[key] = f"{label},{alias},{start},{end}"
            conn.commit()
        return out

    def reserve(
        self, *, local_account_id: int, username: str, device_id: int, start_time: datetime, end_time: datetime
    ) -> dict:
        alias = self.alias(device_id)
        if alias is None:
            raise HomeDeviceError("Unknown device.")
        owner = alias["owner_deployment_id"]
        candidate = self._destination(local_account_id, owner, "DEVICE_RESERVE")
        try:
            result = self._forward(
                local_account_id, candidate, "device_reserve",
                local_device_id=alias["remote_device_id"],
                start_time=int(start_time.timestamp()),
                end_time=int(end_time.timestamp()),
            )
        except Exception as exc:  # noqa: BLE001
            raise HomeDeviceError(_failure_text(exc)) from None
        reservation = result["payload"]["reservation"]
        salt, hashed, token = generate_token()
        with self._write_lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            cur = conn.execute(
                "INSERT INTO Reservations (username, device_id, start_time, end_time, salt, hash) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    username, int(alias["alias_id"]),
                    datetime.fromtimestamp(int(reservation["start_time"])),
                    datetime.fromtimestamp(int(reservation["end_time"])),
                    salt, hashed,
                ),
            )
            conn.execute(
                "INSERT INTO HomeFederatedReservations "
                "(res_id,owner_deployment_id,remote_reservation_id,local_account_id) VALUES (?,?,?,?)",
                (int(cur.lastrowid), owner, str(reservation["reservation_id"]), int(local_account_id)),
            )
            conn.commit()
        return {"token": token, "res_id": int(cur.lastrowid)}

    def federated_reservation(self, res_id) -> sqlite3.Row | None:
        try:
            res_id = int(res_id)
        except (TypeError, ValueError):
            return None
        with self._connect() as conn:
            return conn.execute(
                "SELECT res_id,owner_deployment_id,remote_reservation_id,local_account_id "
                "FROM HomeFederatedReservations WHERE res_id=?",
                (res_id,),
            ).fetchone()

    def cancel(self, *, local_account_id: int, res_id: int) -> None:
        row = self.federated_reservation(res_id)
        if row is None or int(row["local_account_id"]) != int(local_account_id):
            raise HomeDeviceError("Invalid reservation ID or user does not own reservation.")
        candidate = self._destination(local_account_id, row["owner_deployment_id"], "DEVICE_RESERVE")
        try:
            self._forward(
                local_account_id, candidate, "device_cancel", reservation_id=row["remote_reservation_id"]
            )
        except OwnerSignedFailure as exc:
            # Already gone on the owner: the local routing row is just stale.
            if exc.result["error_code"] != "reservation_not_found":
                raise HomeDeviceError(_failure_text(exc)) from None
        except Exception as exc:  # noqa: BLE001
            raise HomeDeviceError(_failure_text(exc)) from None
        self._delete_local(int(row["res_id"]))

    def _delete_local(self, res_id: int) -> None:
        with self._write_lock, self._connect() as conn:
            conn.execute("DELETE FROM Reservations WHERE res_id=?", (res_id,))
            conn.execute("DELETE FROM HomeFederatedReservations WHERE res_id=?", (res_id,))

    def _purge_expired_locked(self, conn) -> None:
        conn.execute(
            "DELETE FROM HomeFederatedReservations WHERE res_id IN "
            "(SELECT h.res_id FROM HomeFederatedReservations h "
            " LEFT JOIN Reservations r ON r.res_id=h.res_id "
            " WHERE r.res_id IS NULL OR r.end_time < ?)",
            (datetime.now(),),
        )

    # -- device RPC ------------------------------------------------------

    def resolve_token(self, token) -> dict | None:
        """The federated route a HOME-minted device token names, or None."""

        if type(token) is not str or not token:
            return None
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT r.res_id, r.salt, r.hash, a.alias_id, a.owner_deployment_id, "
                "a.remote_device_id, h.local_account_id, h.remote_reservation_id "
                "FROM HomeFederatedReservations h "
                "JOIN Reservations r ON r.res_id=h.res_id "
                "JOIN FederatedDeviceAliases a ON a.alias_id=r.device_id"
            ).fetchall()
        for row in rows:
            if validate_token(row["salt"], row["hash"], token):
                return dict(row)
        return None

    def account_for_alias(self, alias_id: int) -> int | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT h.local_account_id FROM HomeFederatedReservations h "
                "JOIN Reservations r ON r.res_id=h.res_id WHERE r.device_id=? "
                "ORDER BY r.res_id DESC LIMIT 1",
                (int(alias_id),),
            ).fetchone()
        return int(row[0]) if row else None

    def direct_offer(self, *, local_account_id: int, token: str, ice: str) -> dict:
        """Have the owner answer this client's ICE offer for the reservation
        behind a HOME-minted token (docs/deployment-groups.md §7.6).

        Returns the answer plus what the client needs to pin the owner's QUIC
        handshake: the owner's TLS name and CA from its FederationPeers row.
        Without that row there is no direct route, and the client simply
        keeps driving the device through this HOME.
        """

        route = self.resolve_token(token)
        if route is None or int(route["local_account_id"]) != int(local_account_id):
            raise HomeDeviceError("That token does not name a partner device of yours.")
        owner = route["owner_deployment_id"]
        peer = self.outbound.peer(owner)
        if peer is None:
            raise HomeDeviceError("No direct route to the partner lab is known yet.")
        candidate = self._destination(local_account_id, owner, "DEVICE_CONTROL")
        try:
            result = self._forward(
                local_account_id, candidate, "direct_open",
                reservation_id=str(route["remote_reservation_id"]), ice=ice,
            )
        except Exception as exc:  # noqa: BLE001
            raise HomeDeviceError(_failure_text(exc)) from None
        return {
            "ice": result["payload"]["ice"],
            "server_name": peer["tls_server_name"],
            "ca_pem": peer["ca_pem"],
            "owner": owner,
        }

    def rpc(self, *, local_account_id: int, alias, function_name: str, args: dict) -> dict:
        """Run one device RPC on the owner; returns the owner's results map."""

        candidate = self._destination(local_account_id, alias["owner_deployment_id"], "DEVICE_CONTROL")
        request = grpc_pb2.GenericRPCRequest(function_name=function_name)
        for key, value in args.items():
            if key in ("a", "token"):
                continue
            request.args[key].CopyFrom(value)
        request_b64 = encode_device_b64(
            request.SerializeToString(), code="request_too_large", max_bytes=MAX_DEVICE_ACTION_REQUEST_BYTES
        )
        try:
            result = self._forward(
                local_account_id, candidate, "device_rpc",
                local_device_id=alias["remote_device_id"], request_b64=request_b64,
            )
        except Exception as exc:  # noqa: BLE001
            raise HomeDeviceError(_failure_text(exc)) from None
        raw = decode_device_b64(
            result["payload"]["response_b64"], code="invalid_device_response",
            max_bytes=MAX_DEVICE_RESULT_BYTES, allow_empty=True,
        )
        response = grpc_pb2.GenericRPCResponse()
        response.ParseFromString(raw)
        return dict(response.results)
