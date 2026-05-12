import sqlite3

def get_user(user_id):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()

def update_status(uid, status):
    cursor.execute("UPDATE users SET status = ? WHERE id = ?", (status, uid))

# Plain string queries are fine if there are no variables
def get_all():
    cursor.execute("SELECT * FROM users")
