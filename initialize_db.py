import os
import sqlite3

# ============================================================
# DATABASE CONFIGURATION
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "candidates.db")


def get_connection():
    """Create and return a database connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create the candidates table if it doesn't exist."""

    try:
        with get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS candidates (
                    gmail TEXT NOT NULL,
                    name TEXT NOT NULL,
                    course TEXT NOT NULL,
                    title TEXT NOT NULL,
                    certificate_name TEXT NOT NULL,
                    certificate_data TEXT NOT NULL,
                    PRIMARY KEY (gmail, title)
                )
            """)
            conn.commit()

        print("✅ Database initialized successfully.")

    except sqlite3.Error as e:
        print(f"❌ Database initialization failed: {e}")


def get_certificates(gmail):
    """
    Return all certificates belonging to a Gmail address.
    """

    try:
        with get_connection() as conn:
            rows = conn.execute("""
                SELECT
                    title,
                    certificate_name
                FROM candidates
                WHERE gmail = ?
                ORDER BY title
            """, (gmail,)).fetchall()

        return rows

    except sqlite3.Error as e:
        print(f"❌ Database error: {e}")
        return []


if __name__ == "__main__":
    init_db()