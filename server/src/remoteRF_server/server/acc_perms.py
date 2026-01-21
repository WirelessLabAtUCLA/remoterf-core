import sqlite3
import threading
from typing import Tuple 
from pathlib import Path
from datetime import datetime

from functools import wraps

from ..common.utils import *
from .device_manager import get_all_devices
from .user_groups import user_group_handler

class userperms:
    def __init__(self): # default user perms settings
        self.id = 'user'
        # self.max_reservations = 1
        # self.max_reservation_time_sec = 1800  # half a hour
        # self.devices_allowed = [0] # ex: only pluto
        
        # can only cancel personal reservations, and can only view reservations on the devices they have access to
        
    # def __str__(self):
    #     return f"Max Reservations: {self.max_reservations}\nMax Reservation Time: {int(self.max_reservation_time_sec/60)} minutes\nDevice IDs Accessible: {self.devices_allowed}"

class perms_db:
    def __init__(self):
        self.filepath = Path(__file__).resolve().parent.parent/'db'/'perms.db'
        self.db = sqlite3.connect(self.filepath)
        self.cursor = self.db.cursor()
        
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS Users (
            UserID INTEGER PRIMARY KEY AUTOINCREMENT,
            Username TEXT NOT NULL UNIQUE
        );
        ''')
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS PowerUsers (
                UserID INTEGER PRIMARY KEY AUTOINCREMENT,
                Username TEXT NOT NULL UNIQUE,
                MaxReservations INTEGER NOT NULL,
                MaxReservationTimeSec INTEGER NOT NULL,
                DevicesAllowed TEXT NOT NULL
            );
        ''')

        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS Admins (
                AdminID INTEGER PRIMARY KEY AUTOINCREMENT,
                Username TEXT NOT NULL UNIQUE
            );
        ''')

        self.db.commit()
        self.cursor.close()
        self.db.close()
        self.userperms = userperms()
        self.lock = threading.Lock()
        self.min_reservation_time_sec = 600 # 10 minutes

    @db_connection
    def get_perms(self, username) -> Tuple[str, list[int], int, int]:
        # SQL query to search for a user in all three tables
        query = """
        SELECT 'Normal User' as Type, UserID, Username, NULL as MaxReservations, NULL as MaxReservationTimeSec, NULL as DevicesAllowed FROM Users WHERE Username = ?
        UNION ALL
        SELECT 'Power User', UserID, Username, MaxReservations, MaxReservationTimeSec, DevicesAllowed FROM PowerUsers WHERE Username = ?
        UNION ALL
        SELECT 'Admin', AdminID as UserID, Username, NULL, NULL, NULL FROM Admins WHERE Username = ?
        """

        # Execute the query
        self.cursor.execute(query, (username, username, username))

        # Fetch all results
        results = self.cursor.fetchall()
        
        # print(f"Results: {results}")

        # Return the results
        return results
    
    @db_connection 
    def get_normal_user_uid(self, username:str) -> int:
        # SQL query to select the UserID from the Users table
        query = 'SELECT UserID FROM Users WHERE Username = ?'

        # Execute the query
        self.cursor.execute(query, (username,))

        # Fetch the result
        result = self.cursor.fetchone()

        # Return the UserID or -1 if not found
        return result[0] if result else -1
        

    def validate_reservation_request(self, accid, username, device_id, start_time, end_time, current_reservation_count:int, is_server=False, reserved_device_ids=[]) -> Tuple[bool, str]:
        # check basic reservation requirements
        if start_time > end_time:
            return False, 'Start time must be before end time'
        if end_time < datetime.now():
            return False, 'End time must not be in the past'
        
        # check if device exists
        devices = get_all_devices()
        if device_id not in devices:
            return False, 'Invalid device ID. Device either does not exist or is disconnected.'
        
        # check reservation duration
        reservation_duration = (end_time - start_time).total_seconds()
        if reservation_duration < 600:
            return False, 'Minimum reservation time is 10 minutes.'
        
        if is_server:
            return True, ''
        
        # Perm check
        perms = self.get_perms(username)[0]
        
        if perms[0] == 'Normal User':
            
            uid = accid
            
            allowed_res, max_res = user_group_handler.get_users_max_reservations(uid=uid, device_id=device_id)
            allowed_time, max_time = user_group_handler.get_users_max_reservation_time(uid=uid, device_id=device_id)

            if not allowed_res or not allowed_time:
                return False, 'Invalid device ID. Device either does not exist or is disconnected.'

            # check if user has reached max reservations
            # if current_reservation_count >= max_res:
            #     return False, 'User has reached max reservations.'
            
            allowed_res, group_used, group_max, _gid = user_group_handler.get_group_quota_for_device(
                uid=uid,
                device_id=device_id,
                reserved_device_ids=reserved_device_ids,
            )

            if not allowed_res:
                return False, 'Invalid device ID. Device either does not exist or is disconnected.'

            if group_used >= group_max:
                return False, 'User has reached max reservations.'

            # check if user has reached max reservation time
            if reservation_duration > max_time:
                return False, f'Max Reservation Duration allowed is {max_time/60} minutes.'

            # # check if user has reached max reservations
            # max_reservation_info = user_group_handler.get_users_max_reservations(uid=uid, device_id=device_id)
            # if max_reservation_info[0] and current_reservation_count >= max_reservation_info[1]:
            #     return False, 'User has reached max reservations.'
            
            # # check if user has reached max reservation time
            # max_duration_time_info = user_group_handler.get_users_max_reservation_time(uid=uid, device_id=device_id)
            # if max_duration_time_info[0] and reservation_duration > max_duration_time_info[1]:
            #     return False, f'Max Reservation Duration allowed is {max_duration_time_info[1]/60} minutes.'
        
            # check if user has permission to reserve device
            # if device_id not in self.userperms.devices_allowed:
            #     return False, 'Invalid device ID. Device either does not exist or is disconnected.'
            
            # # check if user has reached max reservations
            # if current_reservation_count >= self.userperms.max_reservations:
            #     return False, 'User has reached max reservations.'
            
            # # check if user has reached max reservation time
            # if reservation_duration > self.userperms.max_reservation_time_sec:
            #     return False, f'Max Reservation Duration allowed is {self.userperms.max_reservation_time_sec/60} minutes.'
            
        elif perms[0] == 'Power User':
            # check if user has permission to reserve device
            if device_id not in str_to_list(perms[5]):
                return False, 'Invalid device ID. Device either does not exist or is disconnected.'
            
            # check if user has reached max reservations
            if current_reservation_count >= int(perms[3]):
                return False, f'Max Reservations allowed is {perms[3]}.'
            
            # check if user has reached max reservation time
            if reservation_duration > int(perms[4]):
                return False, f'Max Reservation Duration allowed is {perms[4]/60} minutes.'
            
        elif perms[0] == 'Admin':
            pass # admin has no restrictions
        else:
            return False, 'Perms could not be found. Access Denied.'
        return True, ''

    @db_connection
    def set_user(self, username):
        # SQL command to insert a new user
        insert_query = 'INSERT INTO Users (Username) VALUES (?)'

        try:
            # Execute the SQL command
            self.remove_user(username)
            self.cursor.execute(insert_query, (username,))
            
        except sqlite3.Error as e:
            print("An error occurred:", e)

    @db_connection
    def set_admin(self, username:str):
        print(f"Setting {username} as an admin")
        inpu = input(f"Are you sure you want to set {username} as an admin? \nThis gives them unrestricted access. (Y/N): ") 
        if inpu != 'Y' and inpu != 'y':
            print(f"Admin set is canceled for user: {username}.")
            return
        
        
        # SQL command to insert a new user
        insert_query = 'INSERT INTO Admins (Username) VALUES (?)'

        try:
            # Execute the SQL command
            self.remove_user(username)
            self.cursor.execute(insert_query, (username,))
            print("Admin added successfully")
            
        except sqlite3.Error as e:
            print("An error occurred:", e)

    @db_connection
    def set_poweruser(self, username:str, max_reservations:int, max_reservation_time_sec:int, devices_allowed:list[int]):
        
        print(f"Setting {username} as a PowerUser")
        
        # SQL command to insert a new user
        insert_query = 'INSERT INTO PowerUsers (Username, MaxReservations, MaxReservationTimeSec, DevicesAllowed) VALUES (?, ?, ?, ?)'

        try:
            # Execute the SQL command
            self.remove_user(username)
            self.cursor.execute(insert_query, (username, max_reservations, max_reservation_time_sec, list_to_str(devices_allowed)))
            print(f"PowerUser perm for {username} added successfully")
            
        except sqlite3.Error as e:
            print("An error occurred:", e)
            return


    def remove_user(self, username:str) -> bool:
        # List of tables to check
        tables = ['Users', 'PowerUsers', 'Admins']

        try:
            # Attempt to delete the user from each table
            for table in tables:
                self.cursor.execute(f'DELETE FROM {table} WHERE Username = ?', (username,))

        except sqlite3.Error as e:
            print("An error occurred:", e)
            
    @db_connection
    def delete_user_from_reservation_handler(self, username:str):
        self.remove_user(username)
    
    @db_connection
    def print_perms(self):
        print("Printing all permissions:")
        print("Users:")
        # SQL query to select all users from the Users table
        query = 'SELECT * FROM Users'

        # Execute the query
        self.cursor.execute(query)

        # Fetch all results
        results = self.cursor.fetchall()

        # Print the results
        for result in results:
            print(result)
            
        print("\nPowerUsers:")
        # SQL query to select all users from the PowerUsers table
        query = 'SELECT * FROM PowerUsers'
        
        # Execute the query
        self.cursor.execute(query)
        
        # Fetch all results
        results = self.cursor.fetchall()
        
        # Print the results
        for result in results:
            print(result)
            
        print("\nAdmins:")
        # SQL query to select all users from the Admins table
        query = 'SELECT * FROM Admins'
        
        # Execute the query
        self.cursor.execute(query)
        
        # Fetch all results
        results = self.cursor.fetchall()
        
        # Print the results
        for result in results:
            print(result)
    
    @db_connection
    def rm_db(self):
        # SQL command to delete all entries from all tables
        query = 'DELETE FROM Users; DELETE FROM PowerUsers; DELETE FROM Admins'

        # Execute the query
        self.cursor.executescript(query)
            
perms = perms_db()