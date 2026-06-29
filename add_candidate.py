import os
import sqlite3
import base64

# ============================================================
# DATABASE
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "candidates.db")


def add_candidate(gmail, name, course, certificate_filename, title):
    """
    Add or update a candidate certificate in the database.
    """

    certificate_path = os.path.abspath(certificate_filename)

    if not os.path.isfile(certificate_path):
        print(f"❌ Certificate not found: {certificate_filename}")
        return

    # Read the entire file (DO NOT truncate)
    with open(certificate_path, "rb") as file:
        encoded_data = base64.b64encode(file.read()).decode("utf-8")

    # Store only the filename, not the full path
    file_name = os.path.basename(certificate_filename)

    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()

            cursor.execute("""
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

            cursor.execute("""
                INSERT OR REPLACE INTO candidates
                (gmail, name, course, title, certificate_name, certificate_data)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                gmail,
                name,
                course,
                title,
                file_name,
                encoded_data
            ))

            conn.commit()

            print(f"✅ Certificate '{title}' saved successfully for {gmail}")

    except sqlite3.Error as e:
        print(f"❌ Database Error: {e}")


# ============================================================
# Example
# ============================================================

if __name__ == "__main__":
    add_candidate(
        "testuser@gmail.com",
        "John Doe",
        "Python Development",
        "testuser_certificate.pdf",
        "Internship Completion"
    )

    add_candidate(
        "testuser2@gmail.com",
        "Alice Smith",
        "Data Science",
        "testuser_certificate_2.pdf",
        "Completion Certificate"
    )