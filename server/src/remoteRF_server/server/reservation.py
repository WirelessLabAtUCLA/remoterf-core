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

import sqlite3
from contextlib import closing
from datetime import datetime
import time
import sys
import threading
import traceback
import json
from collections import deque
from datetime import datetime, timedelta
import re
from uuid import UUID, uuid4, uuid5

from ..common.utils import *
from ..common.utils.api_token import hash_password, verify_password
from remoterf_federation_core import (
    canonical_uuid,
    federated_identity,
    federated_proxy_adapter,
)
from .device_manager import (
    device_inventory_snapshot,
    find_device_id_by_handle,
    get_all_devices,
    reservation_bridge_token,
    get_registered_devices,
    set_device,
    get_all_devices_str,
    start_transmitter,
)
from .acc_perms import perms
from .user_group_handler import user_group_handler
from . import global_onboarding
from .global_onboarding import RELAYED, lan_only_hint
from .federation.migrations import (
    FEDERATED_PASSWORD_HASH,
    FEDERATED_PASSWORD_SALT,
    configure_connection,
    migrate_gate_h_reservations_schema,
    migrate_reservations_schema,
)

allow_connections = True

def _parse_reservation_datetime(value) -> datetime:
    """Parse SQLite timestamps with or without fractional seconds."""
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(str(value).strip())
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"invalid reservation timestamp: {value!r}"
            ) from exc
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone().replace(tzinfo=None)
    return parsed


# Brute-force limiter. Keyed on username (or a global bucket for enrollment
# codes), never on IP: relayed clients all arrive as 127.0.0.1.
_LIMIT_WINDOW_SEC = 300
_LOGIN_LIMIT = 10
_ENROLL_LIMIT = 60
_failures: dict[str, deque] = {}
_failures_lock = threading.Lock()


def _limited(key: str, limit: int) -> bool:
    now = time.monotonic()
    with _failures_lock:
        q = _failures.get(key)
        if q is None:
            return False
        while q and q[0] <= now - _LIMIT_WINDOW_SEC:
            q.popleft()
        if not q:
            del _failures[key]
            return False
        return len(q) >= limit


def _record_failure(key: str) -> None:
    now = time.monotonic()
    with _failures_lock:
        if len(_failures) > 1000:  # a username spray must not grow this forever
            for k in [k for k, q in _failures.items() if q[-1] <= now - _LIMIT_WINDOW_SEC]:
                del _failures[k]
        _failures.setdefault(key, deque()).append(now)


def _clear_failures(key: str) -> None:
    with _failures_lock:
        _failures.pop(key, None)


class ReservationHandler:
    def __init__(self):
        self.federation_enroller = None
        self.federation_permissions = None
        self.federation_devices = None
        self.filepath = get_db_dir() / "reservations.db"
        # self.filepath = Path(__file__).resolve().parent.parent/'db'/'reservations.db'
        
        self.db = sqlite3.connect(self.filepath)
        self.cursor = self.db.cursor()

        migrate_reservations_schema(self.db)
        migrate_gate_h_reservations_schema(self.db)

        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS Reservations (
            res_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            device_id INTEGER NOT NULL,
            start_time TIMESTAMP NOT NULL,
            end_time TIMESTAMP NOT NULL,
            salt TEXT NOT NULL,
            hash TEXT NOT NULL
        )
        ''')
        
        self.cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_reservations_device_id ON Reservations(device_id);
        ''')

        # "Stay logged in" for the deployment protocol: a random token the
        # client keeps instead of the password. Only its hash lives here, so
        # the table reveals nothing; a row is revoked by logout or purge.
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS ClientSessions (
            token_hash TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL,
            last_used_at TIMESTAMP NOT NULL
        )
        ''')
        
        self.cursor.close()
        self.db.commit()
        self.db.close()
        self.lock = threading.RLock()
    
    def handle_call(self, *, function_name, args):
        if not allow_connections:
            return {"ACC": map_arg("Server is not accepting connections at the moment. Please try later.")}
        try:    
            if function_name == 'create_user':
                return self.create_user(**args)
            elif function_name == 'reserve_device':
                username = unmap_arg(args['un'])
                password = unmap_arg(args['pw'])
                if self.login_user(username, password) == {"UC": map_arg(f'{username}')}:
                    starttime = datetime.fromtimestamp(unmap_arg(args['st']))
                    endtime = datetime.fromtimestamp(unmap_arg(args['et']))
                    device_id = unmap_arg(args['dd'])
                    if self._federated_alias(device_id) is not None:
                        return self._federated_reserve(username, device_id, starttime, endtime)
                    response = self.reserve_device(username, device_id, starttime, endtime)
                    self.update_devices()
                    return response
                else:
                    return {"ace": map_arg("Invalid login credentials.")}
            elif function_name == 'get_res':
                username = unmap_arg(args['un'])
                password = unmap_arg(args['pw'])
                if self.login_user(username, password) == {"UC": map_arg(f'{username}')}:
                    result = self.grab_all_reservations(username)
                    if self.federation_devices is not None:
                        result.update({k: map_arg(v) for k, v in self.federation_devices.list_reservations(
                            local_account_id=self.get_uid(username), username=username).items()})
                    return result
                else:
                    return {"ace": map_arg("Invalid login credentials.")}
            elif function_name == 'get_dev':
                username = unmap_arg(args['un'])
                password = unmap_arg(args['pw'])
                if self.login_user(username, password) == {"UC": map_arg(f'{username}')}:
                    result = self.grab_all_devices(username)
                    if self.federation_devices is not None:
                        result.update({k: map_arg(v) for k, v in self.federation_devices.list_devices(
                            local_account_id=self.get_uid(username)).items()})
                    return result
                else:
                    return {"ace": map_arg("Invalid login credentials.")}
            elif function_name == 'login':
                username = unmap_arg(args['un'])
                result = self.login_user(username, unmap_arg(args['pw']))
                if "UC" in result and unmap_arg(args.get('remember', map_arg(False))):
                    result = {**result, "token": map_arg(self.issue_session(username))}
                return result
            elif function_name == 'logout':
                self.revoke_session(unmap_arg(args['pw']))
                return {"UC": map_arg("Logged out.")}
            elif function_name == 'direct_offer':
                if 'un' not in args and 'a' in args:
                    # A script with no login: the partner device token is its
                    # own credential, for its own live reservation only.
                    return self._partner_offer(None, args)
                username = unmap_arg(args['un'])
                password = unmap_arg(args['pw'])
                if self.login_user(username, password) == {"UC": map_arg(f'{username}')}:
                    if 'a' in args:
                        return self._partner_offer(self.get_uid(username), args)
                    try:
                        from .direct_path import offer
                    except Exception:  # noqa: BLE001 - aioquic unusable here; the relay carries the calls
                        return {"ace": map_arg("direct path unavailable")}
                    return offer(self._session_hash(password), username, unmap_arg(args['ice']))
                else:
                    return {"ace": map_arg("Invalid login credentials.")}
            elif function_name == 'device_token':
                username = unmap_arg(args['un'])
                password = unmap_arg(args['pw'])
                if self.login_user(username, password) == {"UC": map_arg(f'{username}')}:
                    return self.device_token(username, unmap_arg(args['h']))
                else:
                    return {"ace": map_arg("Invalid login credentials.")}
            elif function_name == 'cancel_res':
                username = unmap_arg(args['un'])
                password = unmap_arg(args['pw'])
                if self.login_user(username, password) == {"UC": map_arg(f'{username}')}:
                    if (self.federation_devices is not None
                            and self.federation_devices.federated_reservation(unmap_arg(args['res_id'])) is not None):
                        return self._federated_cancel(username, unmap_arg(args['res_id']))
                    if self.validate_cancel_reservation(unmap_arg(args['res_id']), username):
                        response = self.remove_reservation(res_id=unmap_arg(args['res_id']))
                        self.update_devices()
                        return response
                    else:
                        return {"ace": map_arg("Invalid reservation ID or user does not own reservation.")}
                else:
                    return {"ace": map_arg("Invalid login credentials.")}
            # elif function_name == 'get_perms':
            #     username = unmap_arg(args['un'])
            #     password = unmap_arg(args['pw'])
            #     if self.login_user(username, password) == {"UC": map_arg(f'{username}')}:
            #         data = perms.get_perms(username)
            #         if data[0][0] == 'Normal User':
            #             return {'UC': map_arg(str(data)), 'details': map_arg(str(perms.userperms))}
            #         return {'UC': map_arg(str(data))}
            #     else:
            #         return {"ace": map_arg("Invalid login credentials.")}

            elif function_name == "get_perms":
                username = unmap_arg(args["un"])
                password = unmap_arg(args["pw"])

                if self.login_user(username, password) == {"UC": map_arg(f"{username}")}:
                    data = perms.get_perms(username)
                    uid = int(self.get_uid(username))
                    home_permissions = None
                    federation_permissions = getattr(
                        self, "federation_permissions", None
                    )
                    if federation_permissions is not None:
                        try:
                            home_permissions = federation_permissions.summary(
                                local_account_id=uid
                            )
                        except Exception:
                            # Federation is additive. A local permission read must
                            # retain its protected pre-Global behavior even when
                            # optional aggregation is misconfigured.
                            home_permissions = None
                        try:
                            self._record_enrollments(uid, home_permissions)
                        except Exception:
                            pass

                    if data and data[0] and data[0][0] == "Normal User":
                        # Force pure ints (defensive)
                        devs_raw = user_group_handler.get_users_devices(uid=uid) or []
                        devs: list[int] = []
                        for d in devs_raw:
                            try:
                                devs.append(int(d))
                            except Exception:
                                continue
                        devs = sorted(set(devs))

                        # caps: force string keys for JSON + client lookups
                        caps: dict[str, dict] = {}
                        for d in devs:
                            _allowed_t, max_t = user_group_handler.get_users_max_reservation_time(uid=uid, device_id=d)
                            _allowed_r, max_r = user_group_handler.get_users_max_reservations(uid=uid, device_id=d)
                            _allowed_h, max_h = user_group_handler.get_users_max_horizon(uid=uid, device_id=d)
                            caps[str(d)] = {
                                "max_reservation_time_sec": int(max_t),
                                "max_reservations": int(max_r),
                                "max_horizon_sec": int(max_h),
                            }

                        groups_raw = user_group_handler.get_groups_user_in(uid=uid) or []
                        groups: list[str] = []
                        for g in groups_raw:
                            if g is None:
                                continue
                            s = str(g).strip()
                            if s:
                                groups.append(s)

                        details = {
                            "devices": devs,
                            "caps": caps,
                            "groups": groups,
                        }
                        if home_permissions is not None:
                            details["home_permissions"] = home_permissions
                        return {
                            "UC": map_arg(str(data)),
                            "details": map_arg(json.dumps(details)),
                        }

                    if home_permissions is not None:
                        return {
                            "UC": map_arg(str(data)),
                            "details": map_arg(
                                json.dumps({"home_permissions": home_permissions})
                            ),
                        }
                    return {"UC": map_arg(str(data))}

                return {"ace": map_arg("Invalid login credentials.")}


                
            elif function_name == 'set_enroll':
                username = unmap_arg(args['un'])
                password = unmap_arg(args['pw'])
                if self.login_user(username, password) == {"UC": map_arg(f'{username}')}:
                    code_name = unmap_arg(args['ec'])
                    acc_id = self.get_uid(username)
                    if _limited("enroll", _ENROLL_LIMIT):
                        return {"UE": map_arg(f"Failed to enroll {username}. Invalid or expired code.")}
                    if code_name.startswith("rrf2."):
                        if self.federation_enroller is None:
                            return {"ace": map_arg("Federated enrollment is unavailable.")}
                        from remoterf_federation_core import (
                            FederationError,
                            OwnerSignedFailure,
                            TransportFailure,
                            canonical_json,
                        )

                        try:
                            result = self.federation_enroller.enroll(
                                local_account_id=acc_id,
                                enrollment_input=code_name,
                            )
                        except OwnerSignedFailure as exc:
                            return {
                                "UE": map_arg(exc.result["error_code"]),
                                "federation_provenance": map_arg("destination"),
                            }
                        except TransportFailure as exc:
                            return {
                                "ace": map_arg(exc.code),
                                "federation_provenance": map_arg("transport"),
                            }
                        except FederationError:
                            _record_failure("enroll")
                            return {"UE": map_arg("Invalid federation invitation.")}
                        if self.federation_devices is not None:
                            self.federation_devices.record_enrollment(
                                local_account_id=acc_id,
                                destination_deployment_id=result["deployment_id"],
                            )
                        return {
                            "UC": map_arg("Federated enrollment confirmed."),
                            "federation": map_arg(canonical_json(result)),
                        }
                    if code_name.startswith("cluster."):
                        from .federation import cluster as cluster_module

                        joined = cluster_module.redeem_code(acc_id, code_name)
                        if joined is None:
                            _record_failure("enroll")
                            return {"UE": map_arg(f"Failed to enroll {username}. Invalid or expired code.")}
                        try:
                            cluster_module.enroll_students(self, only_account=acc_id)
                        except Exception:  # noqa: BLE001 - the tick retries
                            pass
                        return {"UC": map_arg(f"Enrolled {username} in cluster {joined}.")}
                    if RELAYED.get() and user_group_handler.code_is_lan_only(code_name=code_name):
                        return {"UE": map_arg(lan_only_hint("This enrollment code"))}
                    if user_group_handler.code_is_account_only(code_name=code_name):
                        return {"UE": map_arg("This code only creates new accounts; it adds nothing to an existing one.")}
                    if user_group_handler.enroll_user_with_code(uid=acc_id, code_name=code_name):
                        return {'UC': map_arg(f'Enrolled {username}.')}
                    else:
                        _record_failure("enroll")
                        return {'UE': map_arg(f'Failed to enroll {username}. Invalid or expired code.')}
                else:
                    return {"ace": map_arg("Invalid login credentials.")}
            return {"ace": map_arg(f"No matching server function to call: {function_name}")}
        except Exception:
            print(f"ACC:{function_name} failed:", file=sys.stderr)
            traceback.print_exc()
            return {"ace": map_arg("Internal server error; please try again or contact your instructor.")}
        
    # ── HOME device plane (Server-to-Server federation) ────────────────
    # A partner's device is an alias id >= ALIAS_BASE; the owner decides.

    def _federated_alias(self, device_id):
        if self.federation_devices is None:
            return None
        return self.federation_devices.alias(device_id)

    def _federated_reserve(self, username, device_id, start_time, end_time):
        from .federation.home_devices import HomeDeviceError

        try:
            issued = self.federation_devices.reserve(
                local_account_id=self.get_uid(username), username=username,
                device_id=int(device_id), start_time=start_time, end_time=end_time,
            )
        except HomeDeviceError as exc:
            return {"ace": map_arg(str(exc))}
        return {"Token": map_arg(issued["token"])}

    def _partner_offer(self, local_account_id, args):
        """A partner device: the owner answers, over the HOME's grant; the
        client then punches to the owner itself."""
        from .federation.home_devices import HomeDeviceError

        if self.federation_devices is None:
            return {"ace": map_arg("This home has no partner devices.")}
        try:
            answer = self.federation_devices.direct_offer(
                local_account_id=local_account_id,
                token=unmap_arg(args['a']), ice=unmap_arg(args['ice']),
            )
        except HomeDeviceError as exc:
            return {"ace": map_arg(str(exc))}
        return {key: map_arg(value) for key, value in answer.items()}

    def _federated_cancel(self, username, res_id):
        from .federation.home_devices import HomeDeviceError

        try:
            self.federation_devices.cancel(local_account_id=self.get_uid(username), res_id=res_id)
        except HomeDeviceError as exc:
            return {"ace": map_arg(str(exc))}
        return {"UC": map_arg(f'Removed reservation {res_id}')}

    def _record_enrollments(self, uid, home_permissions):
        """A partner that already lists this user in a group has enrolled them."""
        plane = getattr(self, "federation_devices", None)
        if plane is None or not home_permissions:
            return
        for entry in home_permissions.get("federation", []):
            if entry.get("status") == "ok" and entry.get("groups"):
                plane.record_enrollment(
                    local_account_id=uid, destination_deployment_id=entry["deployment_id"]
                )

    @db_connection
    def get_uid(self, username:str) -> int:
        self.cursor.execute("SELECT acc_id FROM Accounts WHERE username = ? LIMIT 1", (username,))
        row = self.cursor.fetchone()
        uid = int(row[0]) if row else -1
        return uid
    
    @db_connection
    def create_user(self,*, un, pw, em, ec, ad:bool=False):
        un = unmap_arg(un)
        pw = unmap_arg(pw)
        em = unmap_arg(em)
        ec = unmap_arg(ec)
        
        # check if username and password fit the bill
        if len(un) < 3:
            return {"UE": map_arg("Username must be at least 3 characters long.")}
        if '@' in un:
            # On Global the full account name is `name@lab`.
            return {"UE": map_arg("Username cannot contain '@'.")}
        if len(pw) < 5:
            return {"UE": map_arg("Password must be at least 5 characters long.")}
        if '@' not in em:
            return {"UE": map_arg("Invalid email address.")}
        
        if _limited("enroll", _ENROLL_LIMIT):
            return {"UE": map_arg("Invalid or expired enrollment code.")}
        try:
            if RELAYED.get() and user_group_handler.code_is_lan_only(code_name=ec):
                return {"UE": map_arg(lan_only_hint("This enrollment code"))}
            if not user_group_handler.validate_enrollment_code(code_name=ec):
                _record_failure("enroll")
                return {"UE": map_arg("Invalid or expired enrollment code.")}
        except Exception:
            _record_failure("enroll")
            return {"UE": map_arg("Invalid or expired enrollment code.")}

        try:
            passwords = hash_password(pw)
            self.cursor.execute('''
            INSERT INTO Accounts
            (username, email, pass_salt, pass_hash, created_at, auth_type)
            VALUES (?, ?, ?, ?, ?, 'local_password')
            ''', (un, em, passwords[0], passwords[1], datetime.now()))
            uid = int(self.cursor.lastrowid)
            self.cursor.execute(
                "INSERT INTO LocalAccountSubjects "
                "(local_account_id, subject_id, status, created_at) "
                "VALUES (?, ?, 'active', ?)",
                (uid, str(uuid4()), int(time.time())),
            )
            from .federation import cluster as cluster_module

            if ec.startswith("cluster."):
                if cluster_module.redeem_code(uid, ec) is not None:
                    try:
                        cluster_module.enroll_students(self, only_account=uid)
                    except Exception:  # noqa: BLE001 - the tick retries
                        pass
            else:
                user_group_handler.enroll_user_with_code(uid=uid, code_name=ec)
                try:
                    cluster_module.admit_account(self, uid)  # public clusters: in now, not next tick
                except Exception:  # noqa: BLE001 - the tick does it on its next pass
                    pass
            perms.set_user(un) # set perms
            return {"UC": map_arg(global_onboarding.account_name(un))}
        except sqlite3.IntegrityError:
            self.db.rollback()
            _record_failure("enroll")
            return {"UE": map_arg("That username or email is already registered.")}
        except Exception:
            self.db.rollback()
            print(f"create_user {un!r} failed:", file=sys.stderr)
            traceback.print_exc()
            return {"UE": map_arg("Registration failed; please contact your instructor.")}
    
    @db_connection
    def remove_user(self, *, username):
        # A federated proxy is an authentication adapter, not the owner of a
        # reservation.  Once that adapter is removed its username becomes
        # indistinguishable from the deliberately-supported legacy
        # accountless reservation shape.  Quarantine those rows in the same
        # transaction so they can never be materialized by update_devices().
        # Native account deletion keeps the historical accountless behavior.
        if self._account_security_state_locked(username) in (
            "federated",
            "incoherent",
        ):
            self.cursor.execute(
                "DELETE FROM Reservations WHERE username = ?", (username,)
            )
        self.cursor.execute('SELECT acc_id FROM Accounts WHERE username = ?', (username,))
        row = self.cursor.fetchone()
        self.cursor.execute('DELETE FROM ClientSessions WHERE username = ?', (username,))
        self.cursor.execute('DELETE FROM Accounts WHERE username = ?', (username,))
        self._forget_account_rows(int(row[0]) if row else None)
        perms.delete_user_from_reservation_handler(username)
        return {"UC": map_arg(f'Removed {username}')}

    def _forget_account_rows(self, uid: int | None) -> None:
        """Everything else keyed by the account (None: by any account), so a
        deleted account is not a ghost the cluster tick keeps enrolling."""
        from .federation import cluster as cluster_module

        where, args = ("WHERE local_account_id = ?", (uid,)) if uid is not None else ("", ())
        for table in ("LocalAccountSubjects", "FederatedEnrollments"):
            try:
                self.cursor.execute(f"DELETE FROM {table} {where}", args)
            except sqlite3.OperationalError:
                pass  # table not present on this deployment
        user_group_handler.forget_user(uid=uid)
        cluster_module.forget_account(uid)
    
    @db_connection
    def validate_cancel_reservation(self, res_id:int, username:str) -> bool:
        self.cursor.execute('SELECT * FROM Reservations WHERE res_id = ?', (res_id,))
        reservation = self.cursor.fetchone()
        if reservation is not None and reservation[1] == username:
            return True
        return False
    
    @db_connection
    def remove_reservation(self, *, res_id):
       self.cursor.execute('DELETE FROM Reservations WHERE res_id = ?', (res_id,))
       return {"UC": map_arg(f'Removed reservation {res_id}')}
    
    @db_connection 
    def rm_db(self):
        if input("Drop Tables? (y/n): ") == 'y' and input("Are you sure? This deletes ALL data stored on the server. (y/n): ") == 'y':
            time.sleep(1)
            if input("Last chance. Are you sure? (y/n): ") == 'y':
                self.cursor.execute('DROP TABLE IF EXISTS Accounts')
                self.cursor.execute('DROP TABLE IF EXISTS Reservations')
                self.cursor.execute('DROP TABLE IF EXISTS ClientSessions')
                perms.rm_db()
                sys.exit()
    
    @db_connection 
    def remove_all_users(self):
        self.cursor.execute('DELETE FROM ClientSessions')
        self.cursor.execute('DELETE FROM Accounts')
        self._forget_account_rows(None)
        print("All accounts removed.")
        
    @db_connection 
    def remove_all_reservations(self):
        self.cursor.execute('DELETE FROM Reservations')
        print("All reservations removed.")
    
    @db_connection
    def login_user(self, username, password):
        limiter_key = f"login:{username}"
        self.cursor.execute(
            "SELECT acc_id, username, pass_salt, pass_hash, auth_type "
            "FROM Accounts WHERE username = ?",
            (username,),
        )
        account = self.cursor.fetchone()

        if account is None:
            _record_failure(limiter_key)
            return {"UE": map_arg("Invalid login details.")}

        state = self._account_security_state_locked(username)
        if account[4] != "local_password" or state != "native":
            _record_failure(limiter_key)
            return {"UE": map_arg("Invalid login details.")}

        # Session tokens first: a cheap lookup, so a remembered client never
        # pays for the password KDF, and a guessing attack on the password
        # cannot lock that client out.
        if not self._session_matches(username, password):
            if _limited(limiter_key, _LOGIN_LIMIT):
                return {"UE": map_arg("Invalid login details.")}
            matches, needs_rehash = verify_password(account[2], account[3], password)
            if not matches:
                _record_failure(limiter_key)
                return {"UE": map_arg("Invalid login details.")}
            if needs_rehash:
                self.cursor.execute(
                    "UPDATE Accounts SET pass_salt = ?, pass_hash = ? WHERE acc_id = ?",
                    (*hash_password(password), int(account[0])),
                )
        _clear_failures(limiter_key)
        if RELAYED.get() and user_group_handler.user_is_lan_only(uid=int(account[0])):
            return {"UE": map_arg(lan_only_hint("This account"))}
        return {"UC": map_arg(f"{username}")}

    # ---- client sessions (deployment protocol "stay logged in") ----

    @staticmethod
    def _session_hash(secret: str) -> str:
        import hashlib

        return hashlib.sha256(str(secret).encode("utf-8")).hexdigest()

    def _session_matches(self, username: str, secret: str) -> bool:
        if not secret or len(str(secret)) < 32:
            return False  # a real password never reaches this; a token is 43 chars
        try:
            self.cursor.execute(
                "SELECT username FROM ClientSessions WHERE token_hash = ?",
                (self._session_hash(secret),),
            )
        except sqlite3.OperationalError:
            return False  # a database that predates sessions has none
        row = self.cursor.fetchone()
        if row is None or row[0] != username:
            return False
        self.cursor.execute(
            "UPDATE ClientSessions SET last_used_at = ? WHERE token_hash = ?",
            (datetime.now(), self._session_hash(secret)),
        )
        return True

    @db_connection
    def issue_session(self, username: str) -> str:
        """A fresh token for a login that just succeeded with the password."""
        import secrets

        token = secrets.token_urlsafe(32)
        now = datetime.now()
        # ponytail: no expiry -- revoked by logout, user removal or purge.
        self.cursor.execute(
            "INSERT INTO ClientSessions (token_hash, username, created_at, last_used_at) "
            "VALUES (?, ?, ?, ?)",
            (self._session_hash(token), username, now, now),
        )
        return token

    @db_connection
    def revoke_session(self, secret: str) -> None:
        self.cursor.execute(
            "DELETE FROM ClientSessions WHERE token_hash = ?", (self._session_hash(secret),)
        )

    def resolve_federated_account(
        self, *, issuer_deployment_id: str, remote_subject_id: str
    ) -> int:
        """Allocate or exactly resolve one proxy for the canonical tuple."""
        identity = federated_identity(issuer_deployment_id, remote_subject_id)
        username, email = federated_proxy_adapter(
            identity.issuer_deployment_id, identity.remote_subject_id
        )
        with self.lock, sqlite3.connect(
            str(self.filepath), timeout=5.0, check_same_thread=False
        ) as conn:
            configure_connection(conn)
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                """
                SELECT b.local_account_id, a.username, a.email, a.pass_salt,
                       a.pass_hash, a.auth_type
                FROM FederatedAccountBindings b
                LEFT JOIN Accounts a ON a.acc_id = b.local_account_id
                WHERE b.issuer_deployment_id = ? AND b.remote_subject_id = ?
                """,
                (identity.issuer_deployment_id, identity.remote_subject_id),
            ).fetchone()
            if row is not None:
                if row[1:] != (
                    username,
                    email,
                    FEDERATED_PASSWORD_SALT,
                    FEDERATED_PASSWORD_HASH,
                    "federated",
                ):
                    raise ValueError("federated account binding is incoherent")
                account_id = int(row[0])
            else:
                collision = conn.execute(
                    "SELECT acc_id FROM Accounts WHERE username = ? OR email = ? LIMIT 1",
                    (username, email),
                ).fetchone()
                if collision is not None:
                    raise ValueError("federated proxy adapter collision")
                conn.execute(
                    """
                    INSERT INTO Accounts
                    (username, email, pass_salt, pass_hash, created_at, auth_type)
                    VALUES (?, ?, ?, ?, ?, 'federated')
                    """,
                    (
                        username,
                        email,
                        FEDERATED_PASSWORD_SALT,
                        FEDERATED_PASSWORD_HASH,
                        datetime.now(),
                    ),
                )
                account_id = int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])
                conn.execute(
                    """
                    INSERT INTO FederatedAccountBindings
                    (issuer_deployment_id, remote_subject_id, local_account_id, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        identity.issuer_deployment_id,
                        identity.remote_subject_id,
                        account_id,
                        int(time.time()),
                    ),
                )
            conn.commit()
        # perms.db is a protected separate database. Insert-if-absent is
        # intentionally idempotent and never resets an existing role.
        perms.ensure_user(username)
        return account_id

    def resolve_federated_principal(
        self,
        *,
        issuer_deployment_id: str,
        remote_subject_id: str,
        display_metadata: dict[str, str] | None = None,
    ):
        account_id = self.resolve_federated_account(
            issuer_deployment_id=issuer_deployment_id,
            remote_subject_id=remote_subject_id,
        )
        from .federation.principals import FederatedPrincipalStore

        store = FederatedPrincipalStore(
            self.filepath.parent / "usergroups.db",
            reservations_path=self.filepath,
        )
        return store.resolve(
            issuer_deployment_id=issuer_deployment_id,
            remote_subject_id=remote_subject_id,
            local_account_id=account_id,
            display_metadata=display_metadata,
        )

    def initialize_native_subjects(self, deployment_id: str) -> dict[int, str]:
        """Persist deterministic bootstrap subjects once for existing natives."""
        deployment_id = canonical_uuid(deployment_id)
        namespace = UUID(deployment_id)
        with self.lock, sqlite3.connect(
            str(self.filepath), timeout=5.0, check_same_thread=False
        ) as conn:
            configure_connection(conn)
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute(
                """
                SELECT a.acc_id
                FROM Accounts a
                LEFT JOIN FederatedAccountBindings b ON b.local_account_id = a.acc_id
                WHERE a.auth_type = 'local_password' AND b.local_account_id IS NULL
                ORDER BY a.acc_id
                """
            ).fetchall()
            for (account_id,) in rows:
                conn.execute(
                    "INSERT OR IGNORE INTO LocalAccountSubjects "
                    "(local_account_id, subject_id, status, created_at) "
                    "VALUES (?, ?, 'active', ?)",
                    (
                        int(account_id),
                        str(uuid5(namespace, f"account:{int(account_id)}")),
                        int(time.time()),
                    ),
                )
            result = {
                int(account_id): canonical_uuid(subject_id)
                for account_id, subject_id in conn.execute(
                    "SELECT local_account_id, subject_id FROM LocalAccountSubjects "
                    "ORDER BY local_account_id"
                )
            }
            conn.commit()
            return result

    @db_connection
    def get_native_subject(self, local_account_id: int) -> str | None:
        self.cursor.execute(
            """
            SELECT s.subject_id
            FROM Accounts a
            JOIN LocalAccountSubjects s ON s.local_account_id = a.acc_id
            LEFT JOIN FederatedAccountBindings b ON b.local_account_id = a.acc_id
            WHERE a.acc_id = ? AND a.auth_type = 'local_password'
              AND s.status = 'active' AND b.local_account_id IS NULL
            """,
            (int(local_account_id),),
        )
        row = self.cursor.fetchone()
        return canonical_uuid(row[0]) if row else None

    @db_connection
    def get_username_by_acc_id(self, acc_id: int) -> str | None:
        self.cursor.execute(
            "SELECT username FROM Accounts WHERE acc_id = ? LIMIT 1", (acc_id,)
        )
        row = self.cursor.fetchone()
        return row[0] if row else None

    @db_connection
    def get_auth_type(self, username: str) -> str | None:
        self.cursor.execute(
            "SELECT auth_type FROM Accounts WHERE username = ? LIMIT 1", (username,)
        )
        row = self.cursor.fetchone()
        return row[0] if row is not None else None

    def _account_security_state_locked(self, username: str) -> str:
        self.cursor.execute(
            """
            SELECT a.auth_type, a.username, a.email, a.pass_salt, a.pass_hash,
                   b.issuer_deployment_id, b.remote_subject_id
            FROM Accounts a
            LEFT JOIN FederatedAccountBindings b ON b.local_account_id = a.acc_id
            WHERE a.username = ?
            """,
            (username,),
        )
        row = self.cursor.fetchone()
        if row is None:
            return "missing"
        auth_type, actual_username, email, salt, hashed, issuer, subject = row
        if auth_type == "local_password" and issuer is None and subject is None:
            return "native"
        if auth_type == "federated" and issuer is not None and subject is not None:
            try:
                expected_username, expected_email = federated_proxy_adapter(
                    issuer, subject
                )
            except Exception:
                return "incoherent"
            if (
                actual_username == expected_username
                and email == expected_email
                and salt == FEDERATED_PASSWORD_SALT
                and hashed == FEDERATED_PASSWORD_HASH
            ):
                return "federated"
        return "incoherent"

    @db_connection
    def get_account_security_state(self, username: str) -> str:
        return self._account_security_state_locked(username)
    
    def _clean_expired_reservations(self, device_id: int):
        """Remove expired reservations from the database."""
        current_time = datetime.now()
        cur = self.db.cursor()
        try:
            cur.execute('DELETE FROM Reservations WHERE device_id = ? AND end_time < ?', (device_id, current_time))
        finally:
            cur.close()
    
    @db_connection
    def get_reserved_device_ids_for_user(self, username: str) -> list[int]:
        """
        Returns one device_id per reservation row that is still active/upcoming.
        Duplicates are intentional (counts reservations, not unique devices).
        """
        try:
            username = str(username).strip()
            if not username:
                return []

            now = datetime.now()
            self.cursor.execute(
                """
                SELECT device_id
                FROM Reservations
                WHERE username = ?
                AND end_time > ?
                """,
                (username, now),
            )
            rows = self.cursor.fetchall() or []

            out: list[int] = []
            for (d,) in rows:
                try:
                    out.append(int(d))
                except Exception:
                    pass
            return out
        except Exception:
            return []
    
    @db_connection 
    def reserve_device(self, username, device_id: int, start_time, end_time, is_server=False):
        
        self._clean_expired_reservations(device_id)
        
        security_state = self._account_security_state_locked(username)
        if security_state in ("federated", "incoherent"):
            return {"ace": map_arg("Federated principals cannot reserve resources.")}

        self.cursor.execute("SELECT acc_id FROM Accounts WHERE username = ? LIMIT 1", (username,))
        row = self.cursor.fetchone()
        accid = int(row[0]) if row else -1
        
        # Check if reservation is valid with perms.
        reserved_device_ids = self.get_reserved_device_ids_for_user(username)
        reserved_device_ids = reserved_device_ids + [int(device_id)]

        validation = perms.validate_reservation_request(
            accid,
            username,
            device_id,
            start_time,
            end_time,
            self.get_reservation_count(username),
            is_server=is_server,
            reserved_device_ids=reserved_device_ids,
        )

        if validation[0] == False:
            return {"ace": map_arg(validation[1])}
        
        # Check if the time slot is already reserved
        self.cursor.execute('SELECT * FROM Reservations WHERE device_id = ? AND start_time < ? AND end_time > ?', (device_id, end_time, start_time))
        
        if self.cursor.fetchone():
            # Time slot is already reserved
            return {"ace": map_arg("Device already reserved at this time. Please select another time or device.")}
        
        token = generate_token()
        
        # Store the reservation and hashed API token in the database
        self.cursor.execute('INSERT INTO Reservations (username, device_id, start_time, end_time, salt, hash) VALUES (?, ?, ?, ?, ?, ?)',
                       (username, device_id, start_time, end_time, token[0], token[1]))
        return {"Token": map_arg(token[2])}
    
    @db_connection 
    def validate_token(self, *, token, device_id):
        
        # check if the token is valid for the given device_id
        # return 'Valid' if token is valid for the current time stamp (kick any users using atm)
        # return 'Unocc' if no one is using the device at the current time stamp (past 5 minutes)
        # return 'Invalid' o.w.
        
        # TODO: Set for const lookup time for the api token? and perhaps check every minute to see if the token is still valid and then clean out of the list. HAVE the cleaning be on a separate thread.
        
        # TODO: Store the token on the device itself in device manager, and then when the device is being used, it checks itself. Once the time is over, then tokens get replaced and cleaned out on the devices, and so subsquent calls cannot go through.
        
        now = datetime.datetime.now()
        cursor = self.db.cursor()

        # Get the reservation details from the database
        cursor.execute("""
            SELECT * FROM Reservations WHERE start_time < ? AND end_time > ?
        """, (device_id, now, now))
        
        reservations = cursor.fetchone()
        cursor.close()
        
        if reservations is not None and validate_token(reservations[4], reservations[5], token):
            return "Valid"
        elif reservations is None:
            return "Unocc"
        else:
            return "Invalid"
        
    @db_connection
    def grab_all_reservations_server(self):
        self.cursor.execute('SELECT * FROM Reservations')
        reservations = self.cursor.fetchall()
        result = {}
        for res in reservations:
            result[int(res[0])] = res[1:-2]
        return result
        
    @db_connection
    def grab_all_reservations(self, username:str, current_time=datetime.now()):
        self.cursor.execute('SELECT * FROM Reservations')
        reservations = self.cursor.fetchall()
        perm = perms.get_perms(username)[0]
        result = {}

        def masked(res):
            # Other users' rows keep their slot but not their name; same
            # field layout as before (username,device_id,start,end).
            fields = list(res[1:-2])
            if fields[0] != username:
                fields[0] = "reserved"
            return map_arg(','.join(map(str, fields)))

        if perm[0] == 'Admin':
            for i, res in enumerate(reservations, start=1):
                result[f'{res[0]}'] = map_arg(','.join(map(str, res[1:-2])))

        # elif perm[0] == 'Normal User':
        #     normalperms = perms.userperms.devices_allowed
        #     for i, res in enumerate(reservations, start=1):
        #         if res[2] in normalperms:
        #             result[f'{res[0]}'] = map_arg(','.join(map(str, res[1:-2])))

        elif perm[0] == 'Normal User':
            self.cursor.execute("SELECT acc_id FROM Accounts WHERE username = ? LIMIT 1", (username,))
            row = self.cursor.fetchone()
            uid = int(row[0]) if row else -1
            allowed = set(user_group_handler.get_users_devices(uid=uid))

            for i, res in enumerate(reservations, start=1):
                if int(res[2]) in allowed:
                    result[f'{res[0]}'] = masked(res)


        elif perm[0] == 'Power User':
            for i, res in enumerate(reservations, start=1):
                if res[2] in str_to_list(perm[5]):
                    result[f'{res[0]}'] = masked(res)

        return result
    
    def grab_all_devices(self, username:str):
        devices = get_all_devices_str()
        perm = perms.get_perms(username)[0]
        if perm[0] == 'Admin':
            return {str(k): map_arg(str(v)) for k, v in devices.items()}
        
        # if perm[0] == 'Normal User':
        #     normalperms = perms.userperms.devices_allowed
        #     return {str(k): map_arg(str(v)) for k, v in devices.items() if k in normalperms}
        
        if perm[0] == 'Normal User':
            uid = self.get_uid(username)
            allowed = set(user_group_handler.get_users_devices(uid=uid))
            return {str(k): map_arg(str(v)) for k, v in devices.items() if k in allowed}
        
        if perm[0] == 'Power User':
            return {str(k): map_arg(str(v)) for k, v in devices.items() if k in str_to_list(perm[5])}
        
    
    @db_connection 
    def print_all_reservations(self):
        from ..common.utils.panel import print_table

        cursor = self.db.cursor()
        cursor.execute("SELECT res_id, username, device_id, start_time, end_time FROM Reservations")
        columns = ["res_id", "username", "device_id", "start_time", "end_time"]
        rows = [dict(zip(columns, r)) for r in cursor.fetchall() or []]
        cursor.close()
        print_table("Reservations", rows, columns, empty="No reservations found.")
            
    @db_connection
    def get_all_accounts(self):
        cursor = self.db.cursor()
        cursor.execute("SELECT * FROM Accounts")
        accounts = cursor.fetchall()
        cursor.close()
        return accounts
            
    @db_connection    
    def print_all_accounts(self):
        from ..common.utils.panel import print_table

        cursor = self.db.cursor()
        cursor.execute("SELECT acc_id, username, email, created_at, auth_type FROM Accounts")
        names = self._federated_names()
        rows = []
        for acc_id, username, email, created_at, auth_type in cursor.fetchall() or []:
            role = perms.get_perms(username)
            meta = names.get(int(acc_id), {})
            rows.append({
                "username": username,
                "name": meta.get("display_name", ""),
                "role": role[0][0] if role else "",
                "email": email or meta.get("email", ""),
                "auth": auth_type,
                "created_at": created_at,
            })
        cursor.close()
        print_table("Accounts", rows, ["username", "name", "role", "email", "auth", "created_at"], empty="No accounts found.")

    @staticmethod
    def _federated_names() -> dict:
        """What a visiting user's HOME told us about them, by local account id."""
        try:
            with closing(sqlite3.connect(user_group_handler.filepath, timeout=10.0)) as conn:
                rows = conn.execute("SELECT local_account_id, display_metadata_json FROM FederatedPrincipals").fetchall()
            return {int(acc): json.loads(meta or "{}") for acc, meta in rows}
        except (sqlite3.Error, ValueError):
            return {}
            
    @db_connection
    def get_obfuscated_device_reservations_grouped_past_days(self, days: int) -> dict[str, dict[str, int]]:
        try:
            days = int(days)
        except Exception:
            return {}

        if days < 0:
            return {}

        now = datetime.now()
        cutoff = now - timedelta(days=days)

        def _parse_logged_int(v) -> int:
            if isinstance(v, int):
                return v
            if isinstance(v, float):
                return int(v)

            s = str(v).strip()

            # Handles strings like:
            #   "int64_value: 2"
            #   "int64_value: 1772587800"
            if ":" in s:
                s = s.split(":", 1)[1].strip()

            # remove quotes/newlines if present
            s = s.strip().strip('"').strip("'")
            return int(float(s))

        # Take a consistent snapshot of the log file under the same lock used by writers.
        try:
            with log_lock:
                activity_log = _load_logs()
        except Exception:
            activity_log = []

        out: dict[str, dict[str, int]] = {}

        for entry in activity_log:
            try:
                if not isinstance(entry, dict):
                    continue

                if str(entry.get("action", "")).strip() != "reserve_device":
                    continue

                details = entry.get("details", {})
                if not isinstance(details, dict):
                    continue

                args = details.get("args", {})
                result = details.get("result", {})

                if not isinstance(args, dict) or not isinstance(result, dict):
                    continue

                # Only count SUCCESSFUL reservations
                if "Token" not in result:
                    continue

                raw_device_id = args.get("dd")
                raw_start = args.get("st")
                raw_end = args.get("et")

                if raw_device_id is None or raw_start is None or raw_end is None:
                    continue

                device_id = _parse_logged_int(raw_device_id)
                start_ts = _parse_logged_int(raw_start)
                end_ts = _parse_logged_int(raw_end)

                start_dt = datetime.fromtimestamp(start_ts)
                end_dt = datetime.fromtimestamp(end_ts)

                # Same overlap semantics as before
                if end_dt < cutoff or start_dt > now:
                    continue

                dev_key = str(device_id)
                day_key = start_dt.date().isoformat()

                if dev_key not in out:
                    out[dev_key] = {}

                out[dev_key][day_key] = out[dev_key].get(day_key, 0) + 1

            except Exception:
                continue

        return dict(sorted(out.items(), key=lambda kv: int(kv[0])))
    
    @db_connection
    def get_obfuscated_usage_summary(self) -> dict[str, int | float]:

        int_re = re.compile(r'int64_value:\s*([0-9]+)')
        str_re = re.compile(r'string_value:\s*"([^"]*)"')

        def _parse_proto_value(v):
            if isinstance(v, (int, float)):
                return v
            if not isinstance(v, str):
                return v

            m_int = int_re.search(v)
            if m_int:
                return int(m_int.group(1))

            m_str = str_re.search(v)
            if m_str:
                return m_str.group(1)

            return v

        try:
            with log_lock:
                activity_log = _load_logs()
        except Exception:
            activity_log = []

        accounts: set[str] = set()
        total_reservations = 0
        total_reserved_seconds = 0

        for entry in activity_log:
            try:
                if not isinstance(entry, dict):
                    continue

                action = entry.get("action")
                username = entry.get("username")
                details = entry.get("details", {}) or {}
                args = details.get("args", {}) or {}
                result = details.get("result", {}) or {}

                if not isinstance(args, dict) or not isinstance(result, dict):
                    continue

                # Count accounts from successful logins
                if action == "login" and "UC" in result:
                    uc_name = _parse_proto_value(result.get("UC"))
                    if uc_name:
                        accounts.add(str(uc_name))
                    elif username:
                        accounts.add(str(username))

                # Count reservations + reserved time
                if action == "reserve_device":
                    total_reservations += 1

                    st = _parse_proto_value(args.get("st"))
                    et = _parse_proto_value(args.get("et"))

                    if isinstance(st, int) and isinstance(et, int) and et > st:
                        total_reserved_seconds += (et - st)

            except Exception:
                continue

        return {
            "account_count": len(accounts),
            "total_reservations": int(total_reservations),
            "total_reserved_hours": round(total_reserved_seconds / 3600.0, 1),
        }
            
    def get_reservation_count(self, username):
        self.cursor.execute("SELECT COUNT(*) FROM Reservations WHERE username = ?", (username,))
        count = self.cursor.fetchone()[0]
        return count
    
    # @db_connection
    # def update_devices(self):
    #     devices = get_all_devices()
    #     for device_id in list(devices.keys()):
    #         self._clean_expired_reservations(device_id)
            
    #     self.cursor.execute('SELECT * FROM Reservations')
    #     reservations = self.cursor.fetchall()
        
    #     reservations_now = 0
        
    #     for reservation in reservations:    # Update tokens for each device
    #         if datetime.strptime(reservation[3], '%Y-%m-%d %H:%M:%S') <= datetime.now() and datetime.strptime(reservation[4], '%Y-%m-%d %H:%M:%S') > datetime.now():
    #             del devices[reservation[2]]
    #             set_device(reservation[2], reservation[5], reservation[6])
                
    #             # if not get_transmitter_state(): # Turn transmitter on
    #             #     start_transmitter()
                    
    #             reservations_now += 1
                
    #     if reservations_now == 0: # Turn transmitter off if no resservations
    #         # terminate_transmitter()
    #         pass
                
    #     for device in devices:
    #         set_device(device, '', '')
    
    from datetime import datetime

    # ── Federated device plane ───────────────────────────────────────
    #
    # These entry points are reachable ONLY from the federation destination
    # executor, after it has verified a one-time Ed25519 grant bound to an
    # active bilateral contract that allows the matching capability. They
    # deliberately do not accept a password and never call login_user(), so
    # the native containment of proxy accounts (a federated principal has no
    # usable native credential) is unchanged. Local permissions, quotas,
    # overlap, and Policy B eligibility are enforced by exactly the same code
    # a native reservation goes through.

    def _federated_reservation_authorized(self, res_id: int) -> bool:
        row = self.cursor.execute(
            "SELECT 1 FROM FederatedReservations WHERE res_id = ? LIMIT 1",
            (int(res_id),),
        ).fetchone()
        return row is not None

    @db_connection
    def device_token(self, username, handle):
        """`handle` (which may be a raw token: never log it) as a token for the
        caller's own live reservation on that device: a bridge token bound to
        it. Anything that is not a handle comes back unchanged, for the device
        plane to judge. The refusal never says who holds the device."""
        gid = find_device_id_by_handle(handle)
        if gid is None:
            return {"Token": map_arg(handle)}
        why = {"Token": map_arg(handle), "why": map_arg(f"no active reservation of yours on {handle} right now")}
        # update_devices() applied the federated/incoherent filters to the live
        # pair, but leaves an offline device's pair and expired rows alone:
        # require connected and re-check the window.
        entry = get_all_devices().get(gid)
        if not entry or not (entry[1] and entry[2]):
            return why
        row = self.cursor.execute(
            "SELECT res_id, username, start_time, end_time FROM Reservations "
            "WHERE device_id = ? AND salt = ? AND hash = ?",
            (int(gid), entry[1], entry[2]),
        ).fetchone()
        if row is None or row[1] != username or not (
            _parse_reservation_datetime(row[2]) <= datetime.now() < _parse_reservation_datetime(row[3])
        ):
            return why
        try:
            token = reservation_bridge_token(gid, expect=(entry[1], entry[2]))
        except RuntimeError:
            return why
        return {"Token": map_arg(token), "res_id": map_arg(int(row[0]))}

    @db_connection
    def federated_visible_devices(self, *, local_account_id: int) -> list[dict]:
        """Devices this federated principal is permitted to see.

        Permission comes from the destination's own group/role tables, the
        same source a native listing uses, so a federation peer cannot widen
        what its users can see by asking differently.
        """

        username = self._username_for_account_locked(int(local_account_id))
        if username is None:
            return []
        allowed = self._permitted_device_ids_locked(username)
        inventory = device_inventory_snapshot()
        entries = []
        for gid, info in sorted(inventory.items(), key=lambda kv: int(kv[0])):
            if allowed is not None and int(gid) not in allowed:
                continue
            entry = {
                "local_device_id": str(int(gid)),
                "display_name": str(info.get("name") or f"device {gid}"),
                "device_type": info.get("device_type") or None,
                "online": bool(info.get("online")),
                "max_reservation_time_sec": self._device_block_seconds_locked(
                    username, int(gid)
                ),
            }
            if info.get("handle"):
                entry["handle"] = info["handle"]
            entries.append(entry)
        return entries

    @db_connection
    def federated_reserve(
        self,
        *,
        local_account_id: int,
        device_id: int,
        start_time: datetime,
        end_time: datetime,
        issuer_deployment_id: str,
        remote_subject_id: str,
        contract_id: str,
        contract_version: int,
        request_id: str,
        lab_max_reservations: int | None = None,
    ) -> dict:
        """Create one reservation for a federated principal, idempotently.

        Returns the reservation, or {"error": <code>} for an ordinary local
        refusal (permission, quota, conflict, unknown device, bad interval).
        `lab_max_reservations` bounds what the principal's whole home lab may
        hold here at once: per-user quotas alone do not bound a lab that can
        mint accounts.
        The plaintext device token is never returned: it stays inside this
        deployment and is materialized straight onto the device.
        """

        issuer = canonical_uuid(issuer_deployment_id)
        subject = canonical_uuid(remote_subject_id)
        request_id = canonical_uuid(request_id)

        existing = self.cursor.execute(
            "SELECT r.res_id, r.device_id, r.start_time, r.end_time "
            "FROM FederatedReservations f "
            "JOIN Reservations r ON r.res_id = f.res_id "
            "WHERE f.issuer_deployment_id = ? AND f.request_id = ?",
            (issuer, request_id),
        ).fetchone()
        if existing is not None:
            return {
                "reservation_id": str(int(existing[0])),
                "local_device_id": str(int(existing[1])),
                "start_time": int(_parse_reservation_datetime(existing[2]).timestamp()),
                "end_time": int(_parse_reservation_datetime(existing[3]).timestamp()),
            }

        username = self._username_for_account_locked(int(local_account_id))
        if username is None:
            return {"error": "principal_unknown"}
        if self._account_security_state_locked(username) != "federated":
            return {"error": "principal_not_federated"}

        device_id = int(device_id)
        self._clean_expired_reservations(device_id)

        reserved_device_ids = self.get_reserved_device_ids_for_user(username)
        reserved_device_ids = reserved_device_ids + [device_id]
        validation = perms.validate_reservation_request(
            int(local_account_id),
            username,
            device_id,
            start_time,
            end_time,
            self.get_reservation_count(username),
            is_server=False,
            reserved_device_ids=reserved_device_ids,
        )
        if validation[0] is False:
            return {"error": "reservation_refused", "detail": str(validation[1])}

        if lab_max_reservations is not None:
            held = self.cursor.execute(
                "SELECT COUNT(*) FROM FederatedReservations f "
                "JOIN Reservations r ON r.res_id = f.res_id "
                "WHERE f.issuer_deployment_id = ? AND r.end_time > ?",
                (issuer, datetime.now()),
            ).fetchone()[0]
            if held >= int(lab_max_reservations):
                return {"error": "lab_reservation_limit"}

        self.cursor.execute(
            "SELECT 1 FROM Reservations WHERE device_id = ? AND start_time < ? AND end_time > ?",
            (device_id, end_time, start_time),
        )
        if self.cursor.fetchone():
            return {"error": "reservation_conflict"}

        token = generate_token()
        self.cursor.execute(
            "INSERT INTO Reservations (username, device_id, start_time, end_time, salt, hash) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (username, device_id, start_time, end_time, token[0], token[1]),
        )
        res_id = int(self.cursor.lastrowid)
        self.cursor.execute(
            "INSERT INTO FederatedReservations "
            "(res_id, issuer_deployment_id, remote_subject_id, local_account_id, "
            "contract_id, contract_version, request_id, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                res_id,
                issuer,
                subject,
                int(local_account_id),
                canonical_uuid(contract_id),
                int(contract_version),
                request_id,
                int(time.time()),
            ),
        )
        return {
            "reservation_id": str(res_id),
            "local_device_id": str(device_id),
            "start_time": int(start_time.timestamp()),
            "end_time": int(end_time.timestamp()),
        }

    @db_connection
    def federated_reservations(self, *, local_account_id: int) -> list[dict]:
        """Reservations on devices this federated principal may see.

        Rows the principal does not own are returned as occupancy only, with
        an opaque label instead of the owning account's username.
        """

        username = self._username_for_account_locked(int(local_account_id))
        if username is None:
            return []
        allowed = self._permitted_device_ids_locked(username)
        rows = self.cursor.execute(
            "SELECT res_id, username, device_id, start_time, end_time FROM Reservations "
            "ORDER BY device_id, start_time, res_id"
        ).fetchall()
        entries = []
        for res_id, owner, device_id, start, end in rows:
            if allowed is not None and int(device_id) not in allowed:
                continue
            mine = owner == username
            try:
                start_ts = int(_parse_reservation_datetime(start).timestamp())
                end_ts = int(_parse_reservation_datetime(end).timestamp())
            except ValueError:
                continue
            if end_ts <= start_ts:
                continue
            entries.append(
                {
                    "reservation_id": str(int(res_id)),
                    "local_device_id": str(int(device_id)),
                    "display_name": "you" if mine else "reserved",
                    "start_time": start_ts,
                    "end_time": end_ts,
                    "mine": mine,
                }
            )
        return entries

    @db_connection
    def federated_cancel(self, *, local_account_id: int, reservation_id: int) -> dict:
        username = self._username_for_account_locked(int(local_account_id))
        if username is None:
            return {"error": "principal_unknown"}
        row = self.cursor.execute(
            "SELECT r.username FROM Reservations r "
            "JOIN FederatedReservations f ON f.res_id = r.res_id "
            "WHERE r.res_id = ?",
            (int(reservation_id),),
        ).fetchone()
        if row is None or row[0] != username:
            return {"error": "reservation_not_found"}
        self.cursor.execute(
            "DELETE FROM Reservations WHERE res_id = ?", (int(reservation_id),)
        )
        self.cursor.execute(
            "DELETE FROM FederatedReservations WHERE res_id = ?",
            (int(reservation_id),),
        )
        return {"cancelled": True}

    @db_connection
    def federated_live_reservation(
        self,
        *,
        issuer_deployment_id: str,
        remote_subject_id: str,
        reservation_id: int,
        now: datetime | None = None,
    ) -> dict | None:
        """{local_account_id, device_id, username} for a federation-created
        reservation of this exact principal that is live right now, else None."""

        row = self.cursor.execute(
            "SELECT f.local_account_id, r.device_id, r.username, r.start_time, r.end_time "
            "FROM FederatedReservations f JOIN Reservations r ON r.res_id = f.res_id "
            "WHERE f.res_id = ? AND f.issuer_deployment_id = ? AND f.remote_subject_id = ?",
            (int(reservation_id), canonical_uuid(issuer_deployment_id), canonical_uuid(remote_subject_id)),
        ).fetchone()
        if row is None:
            return None
        moment = now or datetime.now()
        try:
            live = _parse_reservation_datetime(row[3]) <= moment < _parse_reservation_datetime(row[4])
        except ValueError:
            return None
        if not live:
            return None
        return {"local_account_id": int(row[0]), "device_id": int(row[1]), "username": row[2]}

    @db_connection
    def federated_active_reservation(
        self, *, local_account_id: int, device_id: int, now: datetime | None = None
    ) -> bool:
        """True only for a federation-created reservation live right now."""

        username = self._username_for_account_locked(int(local_account_id))
        if username is None:
            return False
        moment = now or datetime.now()
        rows = self.cursor.execute(
            "SELECT r.start_time, r.end_time FROM Reservations r "
            "JOIN FederatedReservations f ON f.res_id = r.res_id "
            "WHERE r.username = ? AND r.device_id = ?",
            (username, int(device_id)),
        ).fetchall()
        for start, end in rows:
            try:
                if _parse_reservation_datetime(start) <= moment < _parse_reservation_datetime(end):
                    return True
            except ValueError:
                continue
        return False

    # Helpers below assume the caller already holds the @db_connection cursor.

    def _username_for_account_locked(self, local_account_id: int) -> str | None:
        row = self.cursor.execute(
            "SELECT username FROM Accounts WHERE acc_id = ? LIMIT 1",
            (int(local_account_id),),
        ).fetchone()
        return row[0] if row else None

    def _permitted_device_ids_locked(self, username: str) -> set[int] | None:
        """Permitted device ids, or None for an unrestricted (Admin) role."""

        rows = perms.get_perms(username)
        if not rows:
            return set()
        role = rows[0]
        if role[0] == "Admin":
            return None
        if role[0] == "Power User":
            return {int(x) for x in str_to_list(role[5])}
        uid = self.get_uid(username)
        return {int(x) for x in user_group_handler.get_users_devices(uid=uid)}

    def _device_block_seconds_locked(self, username: str, device_id: int) -> int | None:
        rows = perms.get_perms(username)
        if not rows:
            return None
        role = rows[0]
        try:
            if role[0] == "Power User":
                return int(role[4]) if role[4] else None
            if role[0] == "Normal User":
                # Same source as validate_reservation_request(): the highest
                # max_reservation_time_sec across the groups granting this device.
                allowed, max_seconds = user_group_handler.get_users_max_reservation_time(
                    uid=self.get_uid(username), device_id=int(device_id)
                )
                if not allowed:
                    return None
                return int(max_seconds) if max_seconds else None
        except Exception:
            return None
        return None

    @db_connection
    def update_devices(self):
        devices = get_all_devices()  # whatever your local inventory is

        # Build a lookup: canonical string -> original key in `devices`
        # (handles int keys, str keys, etc.)
        key_by_str = {str(k).strip(): k for k in devices.keys()}

        # Clean expired reservations for devices we actually know locally
        for k in list(devices.keys()):
            self._clean_expired_reservations(str(k).strip())

        self.cursor.execute("SELECT * FROM Reservations")
        reservations = self.cursor.fetchall()

        now = datetime.now()
        reservations_now = 0

        for reservation in reservations:
            start = _parse_reservation_datetime(reservation[3])
            end = _parse_reservation_datetime(reservation[4])

            if start <= now < end:
                security_state = self._account_security_state_locked(reservation[1])
                if security_state == "incoherent":
                    continue
                if security_state == "federated" and not self._federated_reservation_authorized(
                    int(reservation[0])
                ):
                    # An out-of-band row on a proxy account is never honoured.
                    # Only a reservation this deployment itself created from a
                    # verified federation grant carries an authorization record.
                    continue
                dev_id = str(reservation[2]).strip()

                # If this reservation corresponds to a local device, remove it from the "clear later" list.
                orig_key = key_by_str.pop(dev_id, None)
                if orig_key is not None:
                    devices.pop(orig_key, None)  # safe even if already removed

                # Apply reservation token/state for this device_id (local or virtual)
                set_device(dev_id, reservation[5] or "", reservation[6] or "")

                reservations_now += 1

        if reservations_now == 0:
            # terminate_transmitter()
            pass

        # Clear tokens for remaining *local* devices that are not currently reserved
        for k in devices.keys():
            set_device(str(k).strip(), "", "")
        
start_transmitter()
reservation_handler = ReservationHandler()

# region Logging purposes

import numpy as np
import threading
from datetime import datetime
# Path to your activity logs file
LOG_PATH = get_db_dir() / "activity_logs.npy"
log_lock = threading.Lock()

def _load_logs():
    """An empty or truncated log file (a crash mid-write) counts as no entries:
    the next append rewrites it, instead of every append failing forever."""
    if LOG_PATH.exists():
        try:
            return np.load(LOG_PATH, allow_pickle=True).tolist()
        except Exception:  # noqa: BLE001 - EOFError, pickle errors, a 0-byte file
            return []
    return []

def _save_logs(logs):
    # Written beside and renamed over: a crash leaves the old log, not a truncated one.
    tmp = LOG_PATH.with_suffix(".tmp.npy")  # keeps .npy, or np.save appends one
    np.save(tmp, np.asarray(logs, dtype=object), allow_pickle=True)
    tmp.replace(LOG_PATH)

def _append_log(entry: dict):
    """Append a single log entry. Holds log_lock only during file I/O, not during the RPC call."""
    with log_lock:
        logs = _load_logs()
        logs.append(entry)
        _save_logs(logs)

# Store a reference to the original handle_call so we can wrap it
ReservationHandler._original_handle_call = ReservationHandler.handle_call

def sanitize_for_logging(obj):
    """
    Recursively converts non-primitive objects into a string
    representation, so that the object becomes pickleable.
    """
    if isinstance(obj, (str, int, float, bool, type(None))):
        return obj
    elif isinstance(obj, dict):
        return {sanitize_for_logging(key): sanitize_for_logging(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [sanitize_for_logging(item) for item in obj]
    elif isinstance(obj, tuple):
        return tuple(sanitize_for_logging(item) for item in obj)
    else:
        return repr(obj)


# Activity evidence is deliberately an allowlist.  Account arguments and
# result values routinely carry passwords, enrollment invitations/codes,
# reservation credentials, or future token types; adding another redaction
# name must never be required to keep a new secret out of this file.
_SAFE_ACTIVITY_ARGS = {
    "create_user": ("un", "em"),
    "login": ("un",),
    "reserve_device": ("un", "dd", "st", "et"),
    "get_res": ("un",),
    "get_dev": ("un",),
    "get_perms": ("un",),
    "cancel_res": ("un", "res_id"),
    "set_enroll": ("un",),
    "direct_offer": ("un",),
    "device_token": ("un",),
}


def _activity_log_entry(*, function_name, args, result=None, error=None):
    safe_args = {
        name: sanitize_for_logging(args[name])
        for name in _SAFE_ACTIVITY_ARGS.get(function_name, ())
        if name in args
    }
    result_keys = (
        sorted(str(key) for key in result)
        if isinstance(result, dict)
        else []
    )
    username = (
        sanitize_for_logging(unmap_arg(args["un"])) if "un" in args else "N/A"
    )
    return {
        "timestamp": datetime.now().isoformat(),
        "action": function_name,
        "username": username,
        "details": {
            "args": safe_args,
            "outcome": "exception" if error is not None else "returned",
            "result_keys": result_keys,
            "error_type": type(error).__name__ if error is not None else None,
        },
    }

def handle_call_wrapper(self, *, function_name, args):
    """
    Wrapper around the original handle_call.
    The RPC call runs WITHOUT holding log_lock so a slow/stalled disk write
    can never block the server. Logging happens after the call returns.
    """
    # Run the actual RPC — NOT inside log_lock
    try:
        result = self._original_handle_call(function_name=function_name, args=args)
    except Exception as exc:
        entry = _activity_log_entry(
            function_name=function_name, args=args, error=exc
        )
        threading.Thread(target=_append_log, args=(entry,), daemon=True).start()
        raise

    # Log only allowlisted request metadata and result key names.  Never log
    # result values, because successful reservation/enrollment responses may
    # contain reusable credentials.
    entry = _activity_log_entry(
        function_name=function_name, args=args, result=result
    )
    threading.Thread(target=_append_log, args=(entry,), daemon=True).start()

    return result

# Replace the original handle_call with our wrapper
ReservationHandler.handle_call = handle_call_wrapper

# endregion
