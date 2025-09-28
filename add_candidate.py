import sqlite3
import os

def add_candidate(gmail, name, course, certificate_filename, title):
    """Add a candidate to the database with their certificate details."""

    # Ensure the 'candidates' directory exists
    if not os.path.exists("candidates"):
        os.makedirs("candidates")

    certificate_path = os.path.abspath(os.path.join("candidates", certificate_filename))

    if not os.path.isfile(certificate_path):
        print(f"❌ Error: {certificate_filename} not found in 'candidates' directory.")
        return

    try:
        # Connect to the database
        with sqlite3.connect('candidates.db') as conn:
            cursor = conn.cursor()

            # Ensure the candidates table exists
            cursor.execute('''CREATE TABLE IF NOT EXISTS candidates (
                                gmail TEXT, 
                                name TEXT,
                                course TEXT,
                                certificate_path TEXT,
                                title TEXT,
                                PRIMARY KEY(gmail, title))''')

            # Check if the certificate already exists for this Gmail and Title
            cursor.execute("SELECT * FROM candidates WHERE gmail = ? AND title = ?", (gmail, title))
            existing_cert = cursor.fetchone()

            if existing_cert:
                print(f"⚠️ Certificate '{title}' for {gmail} already exists. Updating record.")
                cursor.execute("UPDATE candidates SET name = ?, course = ?, certificate_path = ? WHERE gmail = ? AND title = ?", 
                               (name, course, certificate_path, gmail, title))
            else:
                # Insert the new record
                cursor.execute("INSERT INTO candidates (gmail, name, course, certificate_path, title) VALUES (?, ?, ?, ?, ?)", 
                               (gmail, name, course, certificate_path, title))

            print(f"✅ Candidate {name} ({gmail}) added with certificate '{title}'.")

    except sqlite3.Error as e:
        print(f"⚠️ Database error: {e}")

# Example Usage
add_candidate('testuser@gmail.com', 'John Doe', 'Python Development', 'testuser_certificate.pdf', 'Internship Completion')
add_candidate('testuser2@gmail.com', 'Alice Smith', 'Data Science', 'testuser_certificate_2.pdf', 'Completion Certificate')
