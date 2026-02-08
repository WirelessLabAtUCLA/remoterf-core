# import sqlite3
# from functools import wraps

# def db_connection(func):
#     @wraps(func)
#     def wrapper(self, *args, **kwargs):
#         with self.lock:
#             self.db = sqlite3.connect(self.filepath, check_same_thread=False) 
#             self.cursor = self.db.cursor()
#             result = func(self, *args, **kwargs)
#             self.cursor.close()
#             self.db.commit()
#             self.db.close()
#             return result
#     return wrapper

import sqlite3
from functools import wraps

def db_connection(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        with self.lock:  # make sure self.lock is threading.RLock()
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
