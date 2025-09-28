from flask import Flask, render_template, request, url_for
import sqlite3

app = Flask(__name__)

def get_certificates(gmail):
    """Fetch certificates from the database for the given Gmail."""
    try:
        with sqlite3.connect('candidates.db') as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT certificate_path, name, course, title FROM candidates WHERE gmail = ?", (gmail,))
            certificates = cursor.fetchall()  # List of tuples
        return certificates
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return None

@app.route('/check-certificate', methods=['POST'])
def check_certificate():
    gmail = request.form.get('gmail')
    certificates = get_certificates(gmail)
    return render_template('index.html', certificates=certificates)

if __name__ == '__main__':
    app.run(debug=True)
