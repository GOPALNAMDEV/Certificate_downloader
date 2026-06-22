import sqlite3
import os

DB_NAME = "candidates.db"
UPLOAD_FOLDER = "candidates"


def add_candidate(gmail, name, course, certificate_filename, title):
    """Add or update a candidate certificate."""

    # Create folder if missing
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)

    # Full path only for checking file existence
    full_path = os.path.join(UPLOAD_FOLDER, certificate_filename)

    if not os.path.isfile(full_path):
        print(f"❌ Error: '{certificate_filename}' not found in '{UPLOAD_FOLDER}' folder.")
        return

    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()

            # Create table if it doesn't exist
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

            # Check existing record
            cursor.execute(
                "SELECT 1 FROM candidates WHERE gmail=? AND title=?",
                (gmail, title)
            )

            exists = cursor.fetchone()

            if exists:
                cursor.execute("""
                    UPDATE candidates
                    SET name=?,
                        course=?,
                        certificate_path=?
                    WHERE gmail=? AND title=?
                """, (
                    name,
                    course,
                    certificate_filename,  # store filename only
                    gmail,
                    title
                ))

                print(f"⚠️ Updated existing certificate '{title}' for {gmail}")

            else:
                cursor.execute("""
                    INSERT INTO candidates
                    (gmail, name, course, certificate_path, title)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    gmail,
                    name,
                    course,
                    certificate_filename,  # store filename only
                    title
                ))

                print(f"✅ Added {name} ({gmail})")

            conn.commit()

    except sqlite3.Error as e:
        print(f"❌ Database error: {e}")


# Example records
if __name__ == "__main__":

    add_candidate(
        gmail="testuser@gmail.com",
        name="John Doe",
        course="Python Development",
        certificate_filename="testuser_certificate.pdf",
        title="Internship Completion"
    )

    add_candidate(
        gmail="testuser2@gmail.com",
        name="Alice Smith",
        course="Data Science",
        certificate_filename="testuser_certificate_2.pdf",
        title="Completion Certificate"
    )