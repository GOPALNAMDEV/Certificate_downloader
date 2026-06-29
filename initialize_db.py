import sqlite3
import os

# Path to the SQLite database (can be relative or absolute)
DB_PATH = os.path.join(os.path.dirname(__file__), "candidates.db")

def init_db():
    """
    Initialize the candidates table.
    This function is safe to run multiple times.
    """
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS candidates (
                    gmail TEXT NOT NULL,
                    name TEXT NOT NULL,
                    course TEXT NOT NULL,
                    title TEXT NOT NULL,
                    certificate_name TEXT NOT NULL,
                    certificate_data TEXT NOT NULL,
                    PRIMARY KEY (gmail, title)
                )
            ''')
            conn.commit()
            print("✅ Database initialized successfully.")
    except sqlite3.Error as e:
        print(f"⚠️ Database error: {e}")

def get_certificates(gmail):
    """
    Fetch certificates from the database for the given Gmail.
    Returns a list of tuples: (title, certificate_name)
    """
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT title, certificate_name 
                FROM candidates 
                WHERE gmail = ?
            ''', (gmail,))
            certificates = cursor.fetchall()
        return certificates
    except sqlite3.Error as e:
        print(f"⚠️ Database error: {e}")
        return []

if __name__ == "__main__":
    # Run this file directly to initialize the database
    init_db()
