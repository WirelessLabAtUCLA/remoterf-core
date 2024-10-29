import sqlite3
from functools import wraps

def db_connection(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        with self.lock:
            self.db = sqlite3.connect(self.filepath, check_same_thread=False) 
            self.cursor = self.db.cursor()
            result = func(self, *args, **kwargs)
            self.cursor.close()
            self.db.commit()
            self.db.close()
            return result
    return wrapper