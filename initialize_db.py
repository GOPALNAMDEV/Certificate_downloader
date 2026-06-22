import sqlite3

DB_NAME = "candidates.db"

def initialize_database():
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS candidates (
            gmail TEXT NOT NULL,
            name TEXT NOT NULL,
            course TEXT NOT NULL,
            certificate_path TEXT NOT NULL,
            title TEXT NOT NULL,
            PRIMARY KEY (gmail, title)
        )
        """)

        conn.commit()
        conn.close()

        print("✅ Database initialized successfully.")

    except sqlite3.Error as e:
        print(f"❌ Database error: {e}")

if __name__ == "__main__":
    initialize_database()