import sqlite3
import os
import random
import time
import argparse
from datetime import datetime

DB_FILE = "data/siem.db"

DEPTS = ["Finance", "IT", "HR", "Operations", "Marketing"]
OS_LIST = ["Windows", "macOS", "Linux"]
BROWSERS = ["Chrome", "Edge", "Firefox", "Safari"]

KNOWN_IPS = ["24.84.10.5", "142.58.22.9", "185.220.101.3", "45.133.1.77"]
LOCATIONS = [
    ("Canada", "Vancouver"),
    ("Canada", "Burnaby"),
    ("USA", "Seattle"),
    ("Germany", "Berlin"),
    ("France", "Paris"), 
    ("Russia", "Moscow"),
]
FAIL_REASONS = ["invalid_password", "mfa_failed", "account_locked"]


USER_ADD_PROB = 0.03
DEVICE_ADD_PROB = 0.12
SUCCESS_LOGIN_PROB = 0.80
TIME_BETWEEN_LOOPS_SECONDS = 0.2

SUSPICIOUS_ACTIVITY_PROB = 0.25
SUSPICIOUS_ACTIVITY_SIZE = (12, 30)

IP_MIN_NUM_FAILS = 12
USER_MIN_NUM_FAILS = 8


from datetime import datetime, timezone
def time_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def random_ip():
    # At 60% of the time we get known IP (we do it to have repeated IPs)
    if random.random() < 0.60:
        return random.choice(KNOWN_IPS)
    # At 40%: generate random IP 
    else: 
        return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def create_tables(database):
    with open("schema.sql", "r", encoding = "utf-8") as f:
        database.executescript(f.read())
    database.commit()


def get_ids(cursor, table, id_col):
    return [row[0] for row in cursor.execute(f"SELECT {id_col} FROM {table}")]


def ensure_starters(cursor, database):
    user_ids = get_ids(cursor, "users", "user_id")
    if len(user_ids) == 0:
        cursor.execute(
            "INSERT INTO users(email, dept, role, created_at) VALUES (?,?,?,?)",
            ("starter@company.com", "IT", "admin", time_now())
        )
        database.commit()
        user_ids = get_ids(cursor, "users", "user_id")

    device_ids = get_ids(cursor, "devices", "device_id")
    if len(device_ids) == 0:
        cursor.execute(
            "INSERT INTO devices(device_name, os, browser) VALUES (?,?,?)",
            ("starter-device", "Windows", "Chrome")
        )
        database.commit()
        device_ids = get_ids(cursor, "devices", "device_id")

    return user_ids, device_ids


def insert_user_if_needed(cursor, database, current_user_ids):
    # Keep same list of user ids in 97% of cases
    if random.random() > USER_ADD_PROB:
        return current_user_ids

    dept = random.choice(DEPTS)
    r = random.random()
    if r < 0.75:
        role = "employee"
    elif r < 0.95:
        role = "IT"
    else:
        role = "admin"

    email = f"user_{int(time.time())}_{random.randint(100,1000)}@company.com"

    try:
        cursor.execute(
            "INSERT INTO users(email, dept, role, created_at) VALUES (?,?,?,?)",
            (email, dept, role, time_now())
        )
        database.commit()
        new_id = cursor.lastrowid
        current_user_ids.append(new_id)
        print(f"New user added: {email} (id = {new_id})")
    except sqlite3.IntegrityError:
        pass

    return current_user_ids


def insert_device_if_needed(cursor, database, current_device_ids):
    if random.random() > DEVICE_ADD_PROB:
        return current_device_ids
    
    device_name = f"device_{int(time.time())}_{random.randint(10,99)}"
    os_name = random.choice(OS_LIST)
    browser = random.choice(BROWSERS)

    try:
        cursor.execute(
            "INSERT INTO devices(device_name, os, browser) VALUES (?,?,?)",
            (device_name, os_name, browser)
        )
        database.commit()
        new_id = cursor.lastrowid
        current_device_ids.append(new_id)
        print(f"New device added: {device_name} (id={new_id})")
    except sqlite3.IntegrityError:
        pass

    return current_device_ids


def insert_auth_event(cursor, database, user_id, device_id, ip, country, city, success, reason):
    cursor.execute(
        "INSERT INTO auth_events (ts, user_id, ip, device_id, country, city, success, reason) VALUES (?,?,?,?,?,?,?,?)",
        (time_now(), user_id, ip, device_id, country, city, int(success), reason)
    )
    database.commit()



def simulate_attack(cursor, database, current_user_ids, current_device_ids):
    target_user = random.choice(current_user_ids)
    ip = random_ip()
    country, city = random.choice(LOCATIONS)

    attack = random.randint(*SUSPICIOUS_ACTIVITY_SIZE)
    for _ in range(attack):
        device_id = random.choice(current_device_ids)
        if random.random() < 0.05:
            success = 1
        else: 
            success = 0
        if success:
            reason = None
        else: 
            reason = random.choice (FAIL_REASONS)
        insert_auth_event(cursor, database, target_user, device_id, ip, country, city, success, reason)


def main():
    os.makedirs("data", exist_ok=True)

    database = sqlite3.connect(DB_FILE)
    database.execute("PRAGMA foreign_keys = ON;")
    cursor = database.cursor()

    create_tables(database)
    print("Database is ready!")

    user_ids, device_ids = ensure_starters(cursor, database)

    # NEW: duration support
    parser = argparse.ArgumentParser()
    parser.add_argument("--duration", type=int, default=None,
                        help="Run simulator for N seconds, otherwise run until Ctrl+C.")
    args = parser.parse_args()

    start_time = time.time()

    if args.duration is not None:
        print(f"Generating events for {args.duration} seconds...")
    else:
        print("Generating dynamic users/devices + auth events... Ctrl+C to stop.")

    try:
        while True:
            # NEW: stop condition
            if args.duration is not None and (time.time() - start_time) >= args.duration:
                print("\nDuration reached. Stopping.")
                break

            user_ids = insert_user_if_needed(cursor, database, user_ids)
            device_ids = insert_device_if_needed(cursor, database, device_ids)

            if random.random() < SUSPICIOUS_ACTIVITY_PROB:
                simulate_attack(cursor, database, user_ids, device_ids)
            else:
                user_id = random.choice(user_ids)
                device_id = random.choice(device_ids)
                ip = random_ip()
                country, city = random.choice(LOCATIONS)

                success = random.random() < SUCCESS_LOGIN_PROB
                reason = None if success else random.choice(FAIL_REASONS)

                insert_auth_event(cursor, database, user_id, device_id, ip, country, city, success, reason)

            time.sleep(TIME_BETWEEN_LOOPS_SECONDS)

    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        database.close()


if __name__ == "__main__":
    main()
    
    
