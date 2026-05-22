import sqlite3
from datetime import datetime

def init_db():
    conn = sqlite3.connect('security.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blacklist (
            sender_email TEXT UNIQUE
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT,
            subject TEXT,
            score INTEGER,
            verdict TEXT,
            reasons TEXT,
            timestamp DATETIME
        )
    ''')
    cursor.execute('''
            CREATE TABLE IF NOT EXISTS domain_cache (
                domain TEXT UNIQUE,
                age_days INTEGER,
                timestamp DATETIME
            )
        ''')
    conn.commit()
    conn.close()

def is_in_blacklist(sender_email):
    conn = sqlite3.connect('security.db')
    cursor = conn.cursor()
    cursor.execute('SELECT 1 FROM blacklist WHERE sender_email = ?', (sender_email,))
    result = cursor.fetchone()
    conn.close()
    return result is not None


def add_to_blacklist(sender_email):
    conn = sqlite3.connect('security.db')
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT OR IGNORE INTO blacklist (sender_email) VALUES (?)', (sender_email,))
        conn.commit()
    except Exception as e:
        print(f"Error updating blacklist: {e}")
    finally:
        conn.close()


def log_scan(sender, subject, score, verdict, reasons):
    conn = sqlite3.connect('security.db')
    cursor = conn.cursor()

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    reasons_str = ", ".join(reasons) if reasons else "None"

    cursor.execute('''
        INSERT INTO scans (timestamp, sender, subject, score, verdict, reasons)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (timestamp, sender, subject, score, verdict, reasons_str))

    conn.commit()
    conn.close()

def get_cached_domain_age(domain):
        conn = sqlite3.connect('security.db')
        cursor = conn.cursor()
        cursor.execute('SELECT age_days FROM domain_cache WHERE domain = ?', (domain,))
        result = cursor.fetchone()
        conn.close()
        return result[0] if result else None

def set_cached_domain_age(domain, age_days):
        conn = sqlite3.connect('security.db')
        cursor = conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO domain_cache (domain, age_days, timestamp)
                VALUES (?, ?, ?)
            ''', (domain, age_days, timestamp))
            conn.commit()
        except Exception as e:
            print(f"Error caching domain: {e}")
        finally:
            conn.close()