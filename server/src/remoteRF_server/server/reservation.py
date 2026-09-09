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
from datetime import datetime
import time
import sys
import threading
import json
from datetime import datetime, timedelta
import re
from uuid import UUID, uuid4, uuid5

from ..common.utils import *
from remoterf_federation_core import (
    canonical_uuid,
    federated_identity,
    federated_proxy_adapter,
)
from .device_manager import get_all_devices, set_device, get_all_devices_str, start_transmitter
from .acc_perms import perms
from .user_group_handler import user_group_handler
from .federation.migrations import (
    FEDERATED_PASSWORD_HASH,
    FEDERATED_PASSWORD_SALT,
    configure_connection,
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


class ReservationHandler:
    def __init__(self):
        self.federation_enroller = None
        self.filepath = get_db_dir() / "reservations.db"
        # self.filepath = Path(__file__).resolve().parent.parent/'db'/'reservations.db'
        
        self.db = sqlite3.connect(self.filepath)
        self.cursor = self.db.cursor()

        migrate_reservations_schema(self.db)

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
                    response = self.reserve_device(username, device_id, starttime, endtime)
                    self.update_devices()
                    return response
                else:
                    return {"ace": map_arg("Invalid login credentials.")}
            elif function_name == 'get_res':
                username = unmap_arg(args['un'])
                password = unmap_arg(args['pw'])
                if self.login_user(username, password) == {"UC": map_arg(f'{username}')}:
                    return self.grab_all_reservations(username)
                else:
                    return {"ace": map_arg("Invalid login credentials.")}
            elif function_name == 'get_dev':
                username = unmap_arg(args['un'])
                password = unmap_arg(args['pw'])
                if self.login_user(username, password) == {"UC": map_arg(f'{username}')}:
                    return self.grab_all_devices(username)
                else:
                    return {"ace": map_arg("Invalid login credentials.")}
            elif function_name == 'login':
                return self.login_user(unmap_arg(args['un']), unmap_arg(args['pw']))
            elif function_name == 'cancel_res':
                username = unmap_arg(args['un'])
                password = unmap_arg(args['pw'])
                if self.login_user(username, password) == {"UC": map_arg(f'{username}')}:
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

                    if data and data[0] and data[0][0] == "Normal User":
                        uid = int(self.get_uid(username))

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
                            caps[str(d)] = {
                                "max_reservation_time_sec": int(max_t),
                                "max_reservations": int(max_r),
                            }

                        groups_raw = user_group_handler.get_groups_user_in(uid=uid) or []
                        groups: list[str] = []
                        for g in groups_raw:
                            if g is None:
                                continue
                            s = str(g).strip()
                            if s:
                                groups.append(s)

                        return {
                            "UC": map_arg(str(data)),
                            "details": map_arg(json.dumps({
                                "devices": devs,
                                "caps": caps,
                                "groups": groups,
                            })),
                        }

                    return {"UC": map_arg(str(data))}

                return {"ace": map_arg("Invalid login credentials.")}


                
            elif function_name == 'set_enroll':
                username = unmap_arg(args['un'])
                password = unmap_arg(args['pw'])
                if self.login_user(username, password) == {"UC": map_arg(f'{username}')}:
                    code_name = unmap_arg(args['ec'])
                    acc_id = self.get_uid(username)
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
                            return {"UE": map_arg("Invalid federation invitation.")}
                        return {
                            "UC": map_arg("Federated enrollment confirmed."),
                            "federation": map_arg(canonical_json(result)),
                        }
                    if user_group_handler.enroll_user_with_code(uid=acc_id, code_name=code_name):
                        return {'UC': map_arg(f'Enrolled {username}.')}
                    else:
                        return {'UE': map_arg(f'Failed to enroll {username}. Invalid or expired code.')}
                else:
                    return {"ace": map_arg("Invalid login credentials.")}
            return {"ace": map_arg(f"No matching server function to call: {function_name}")}
        except Exception as e:
            return {"RPC Acc Error", map_arg(f'{e}')}
        
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
        if len(pw) < 5:
            return {"UE": map_arg("Password must be at least 5 characters long.")}
        if '@' not in em:
            return {"UE": map_arg("Invalid email address.")}
        
        try:
            if not user_group_handler.validate_enrollment_code(code_name=ec):
                return {"UE": map_arg("Invalid or expired enrollment code.")}
        except Exception:
            return {"UE": map_arg("Invalid or expired enrollment code.")}
        
        try:
            passwords = hash_token(pw)
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
            user_group_handler.enroll_user_with_code(uid=uid, code_name=ec)
            perms.set_user(un) # set perms
            return {"UC": map_arg(f'{un}')}
        except Exception as e:
            return {"UE": map_arg(f'{e}')}
    
    @db_connection
    def remove_user(self, *, username):
        self.cursor.execute('DELETE FROM Accounts WHERE username = ?', (username,))
        perms.delete_user_from_reservation_handler(username)
        return {"UC": map_arg(f'Removed {username}')}
    
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
                perms.rm_db()
                sys.exit()
    
    @db_connection 
    def remove_all_users(self):
        self.cursor.execute('DELETE FROM Accounts')
        print("All accounts removed.")
        
    @db_connection 
    def remove_all_reservations(self):
        self.cursor.execute('DELETE FROM Reservations')
        print("All reservations removed.")
    
    @db_connection
    def login_user(self, username, password):
        self.cursor.execute(
            "SELECT acc_id, username, pass_salt, pass_hash, auth_type "
            "FROM Accounts WHERE username = ?",
            (username,),
        )
        account = self.cursor.fetchone()

        if account is None:
            return {"UE": map_arg("Invalid login details.")}

        state = self._account_security_state_locked(username)
        if account[4] != "local_password" or state != "native":
            return {"UE": map_arg("Invalid login details.")}

        if validate_token(account[2], account[3], password):
            return {"UC": map_arg(f"{username}")}
        return {"UE": map_arg("Invalid login details.")}

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
                    result[f'{res[0]}'] = map_arg(','.join(map(str, res[1:-2])))

                    
        elif perm[0] == 'Power User':
            for i, res in enumerate(reservations, start=1):
                if res[2] in str_to_list(perm[5]):
                    result[f'{res[0]}'] = map_arg(','.join(map(str, res[1:-2])))
            
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
        print("Printing all reservations...")
        cursor = self.db.cursor()
        cursor.execute("""SELECT * FROM Reservations""")
        reservations = cursor.fetchall()
        cursor.close()
        if reservations is not None:
            for reservation in reservations:
                print("Id:", reservation[0],"Username:", reservation[1], " Device ID:", reservation[2], " Start Time:", reservation[3], " End Time:", reservation[4])
        else:
            print("No reservations found.")
            
    @db_connection
    def get_all_accounts(self):
        cursor = self.db.cursor()
        cursor.execute("SELECT * FROM Accounts")
        accounts = cursor.fetchall()
        cursor.close()
        return accounts
            
    @db_connection    
    def print_all_accounts(self):
        print("Printing all accounts...")
        cursor = self.db.cursor()
        cursor.execute("SELECT * FROM Accounts")
        accounts = cursor.fetchall()
        cursor.close()
        if accounts is not None:
            for account in accounts:
                print("Username:", account[1], f'<{perms.get_perms(account[1])[0][0]}>', " Email:", account[2], " Created At:", account[5])
        else:
            print("No accounts found.")
            
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
                if security_state in ("federated", "incoherent"):
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
    if LOG_PATH.exists():
        return np.load(LOG_PATH, allow_pickle=True).tolist()
    return []

def _save_logs(logs):
    np.save(LOG_PATH, logs, allow_pickle=True)

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

def handle_call_wrapper(self, *, function_name, args):
    """
    Wrapper around the original handle_call.
    The RPC call runs WITHOUT holding log_lock so a slow/stalled disk write
    can never block the server. Logging happens after the call returns.
    """
    # Make a sanitized copy of args before the call (no lock needed here)
    sanitized_args = sanitize_for_logging(dict(args))
    if 'pw' in sanitized_args:
        sanitized_args['pw'] = '*'

    # Run the actual RPC — NOT inside log_lock
    result = self._original_handle_call(function_name=function_name, args=args)

    # Log asynchronously after the call completes
    sanitized_result = sanitize_for_logging(result)
    username = sanitize_for_logging(unmap_arg(args['un'])) if 'un' in args else 'N/A'
    entry = {
        "timestamp": datetime.now().isoformat(),
        "action": function_name,
        "username": username,
        "details": {
            "args": sanitized_args,
            "result": sanitized_result
        }
    }
    threading.Thread(target=_append_log, args=(entry,), daemon=True).start()

    return result

# Replace the original handle_call with our wrapper
ReservationHandler.handle_call = handle_call_wrapper

# endregion
