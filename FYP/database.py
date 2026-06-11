import sqlite3
import datetime

def create_db():
    conn = sqlite3.connect("devices.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            mac TEXT PRIMARY KEY,
            ip TEXT,
            last_seen TEXT
        )
    """)
    conn.commit()
    conn.close()

def save_devices(devices):
    conn = sqlite3.connect("devices.db")
    cursor = conn.cursor()
    for device in devices:
        try:
            cursor.execute(
                "INSERT OR REPLACE INTO devices (mac, ip, last_seen) VALUES (?, ?, ?)",
                (device["mac"], device["ip"], datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            )
        except:
            pass
    conn.commit()
    conn.close()

def check_new_devices(devices):
    conn = sqlite3.connect("devices.db")
    cursor = conn.cursor()
    new_devices = []
    for device in devices:
        cursor.execute("SELECT * FROM devices WHERE mac=?", (device["mac"],))
        if cursor.fetchone() is None:
            new_devices.append(device)
    conn.close()
    return new_devices