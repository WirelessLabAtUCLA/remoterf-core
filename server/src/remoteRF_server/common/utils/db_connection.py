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
from functools import wraps

def db_connection(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        with self.lock:  
            old_db = getattr(self, "db", None)
            old_cursor = getattr(self, "cursor", None)

            conn = sqlite3.connect(str(self.filepath), timeout=5.0, check_same_thread=False)
            try:
                conn.execute("PRAGMA busy_timeout=5000;")
                conn.execute("PRAGMA journal_mode=WAL;")

                cur = conn.cursor()
                self.db = conn
                self.cursor = cur

                try:
                    result = func(self, *args, **kwargs)
                    conn.commit()
                    return result
                except Exception:
                    conn.rollback()
                    raise
                finally:
                    try: cur.close()
                    except Exception: pass
            finally:
                try: conn.close()
                except Exception: pass
                self.db = old_db
                self.cursor = old_cursor
    return wrapper
