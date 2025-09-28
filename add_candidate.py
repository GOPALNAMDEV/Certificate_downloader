import sqlite3
import os
import base64

DB_PATH = "candidates.db"

def add_candidate(gmail, name, course, certificate_filename, title):
    """Add a candidate to the database with their certificate stored as base64 string."""

    # Ensure the certificate file exists
    certificate_path = os.path.abspath(certificate_filename)
    if not os.path.isfile(certificate_path):
        print(f"❌ Error: {certificate_filename} not found.")
        return

    # Read and encode certificate as base64
    with open(certificate_path, "rb") as f:
        file_data = f.read()
        encoded_data = base64.b64encode(file_data).decode('utf-8')
        # Optional: truncate for storage preview
        if len(encoded_data) > 1000:
            encoded_data = encoded_data[:1000]

    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            # Ensure table exists
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

            # Check if record exists
            cursor.execute("SELECT * FROM candidates WHERE gmail=? AND title=?", (gmail, title))
            existing_cert = cursor.fetchone()

            if existing_cert:
                print(f"⚠️ Certificate '{title}' for {gmail} already exists. Updating record.")
                cursor.execute('''
                    UPDATE candidates 
                    SET name=?, course=?, certificate_name=?, certificate_data=? 
                    WHERE gmail=? AND title=?
                ''', (name, course, certificate_filename, encoded_data, gmail, title))
            else:
                cursor.execute('''
                    INSERT INTO candidates (gmail, name, course, title, certificate_name, certificate_data)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (gmail, name, course, title, certificate_filename, encoded_data))

            conn.commit()
            print(f"✅ Candidate {name} ({gmail}) added with certificate '{title}'.")

    except sqlite3.Error as e:
        print(f"⚠️ Database error: {e}")

# Example usage
add_candidate('testuser@gmail.com', 'John Doe', 'Python Development', 'testuser_certificate.pdf', 'Internship Completion')
add_candidate('testuser2@gmail.com', 'Alice Smith', 'Data Science', 'testuser_certificate_2.pdf', 'Completion Certificate')
