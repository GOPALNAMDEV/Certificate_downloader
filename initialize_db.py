import sqlite3

DB_PATH = "candidates.db"

def init_db():
    """Initialize the candidates table with base64 storage for certificates."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS candidates (
                    gmail TEXT,
                    name TEXT,
                    course TEXT,
                    title TEXT,
                    certificate_name TEXT,
                    certificate_data TEXT,
                    PRIMARY KEY (gmail, title)
                )
            ''')
            conn.commit()
            print("✅ Database initialized successfully.")
    except sqlite3.Error as e:
        print(f"⚠️ Database error: {e}")

def get_certificates(gmail):
    """Fetch certificates from the database for the given Gmail."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT title, certificate_name 
                FROM candidates 
                WHERE gmail = ?
            ''', (gmail,))
            certificates = cursor.fetchall()  # List of tuples (title, certificate_name)
        return certificates
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return None

if __name__ == '__main__':
    init_db()
