import sqlite3
from datetime import datetime
import time
import sys
import threading
from pathlib import Path
from functools import wraps

from ..common.utils import *
# from .device_manager import get_all_devices, set_device, get_all_devices_str, start_transmitter, terminate_transmitter, get_transmitter_state
# from .acc_perms import perms, userperms

class UserGroupHandler:
    def __init__(self):
        self.filepath = Path(__file__).resolve().parent.parent/'db'/'usergroups.db'
        self.db = sqlite3.connect(self.filepath)
        self.cursor = self.db.cursor()
        
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS UserGroups (
            group_id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_name TEXT NOT NULL UNIQUE,
            devices_whitelist TEXT NOT NULL DEFAULT '[]',  -- JSON array, e.g. "[0,1,2]"
            max_reservation_time_sec INTEGER NOT NULL,
            max_reservations INTEGER NOT NULL,
            lifetime_sec INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        ''')
        
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS UsersLookup (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id INTEGER
        );
        ''')
        
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS EnrollmentCodes (
            code_id INTEGER PRIMARY KEY AUTOINCREMENT,
            code_name TEXT NOT NULL UNIQUE,
            group_id INTEGER NOT NULL,
            uses INTEGER NOT NULL,
            duration_sec INTEGER NOT NULL
        );
        ''')
        
        self.cursor.close()
        self.db.commit()
        self.db.close()
        self.lock = threading.Lock()
        
    @db_connection    
    def create_user_group(self, *, group_name: str, devices_whitelist: list[int], max_reservation_time_sec: int, max_reservations: int, lifetime_sec: int) -> bool:
        pass
    
    @db_connection
    def delete_user_group(self, *, group_id: int) -> bool:
        # Clean up all associated data in the other tables as well
        pass
    
    @db_connection
    def edit_user_group(self, *, group_id: int, group_name: str = None, devices_whitelist: list[int] = None, max_reservation_time_sec: int = None, max_reservations: int = None, lifetime_sec: int = None) -> bool:
        # simply update the fields provided (non-None): todo: later on clean up any reservations that exceed new limits (for any of the users, etc.) (?)
        pass
    
    @db_connection
    def get_all_user_groups(self, include_users: bool) -> list[dict]:
        # if include_users is True, also return a list of user IDs in each group (just naively search UsersLookup table once)
        pass
    
    @db_connection
    def create_enrollment_code(self, *, code_name: str, group_id: int, uses: int, duration_sec: int) -> str:
        pass
    
    @db_connection
    def create_random_enrollment_codes(self, *, group_id: int, uses: int, duration_sec: int, count: int, char_count: int) -> list[str]:
        # count amount of random codes of char_count length ie: HIGJX34, etc. (alphanumeric)
        # Use the previously implemented create_enrollment code
        pass
    
    @db_connection
    def delete_enrollment_code(self, *, code_name: str) -> bool:
        pass
    
    @db_connection
    def get_all_enrollment_codes(self) -> list[dict]:
        pass
    
    @db_connection
    def enroll_user_with_code(self, *, uid: int, code_name: str) -> bool:
        # Add into users table, and decrement uses in enrollment codes table
        pass
    
    @db_connection
    def get_users_devices(self, *, uid: int) -> list[int]:
        # Union of all devices whitelists from all groups the user is in
        pass
    
    @db_connection 
    def get_users_max_reservation_time(self, *, uid: int, device_id: int) -> int:
        # If the same device shows up in multiple groups, return the highest max_reservation_time_sec
        pass
    
    @db_connection
    def get_users_max_reservations(self, *, uid: int, device_id: int) -> int:
        # If the same device shows up in multiple groups, return the highest max_reservations
        pass
    
    