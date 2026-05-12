import sqlite3

def get_user(user_id):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()

def list_table(table):
    cursor.execute("SELECT * FROM " + table)

def update_status(uid, status):
    cursor.execute("UPDATE users SET status = '%s' WHERE id = %s" % (status, uid))

def search(name):
    cursor.execute("SELECT * FROM products WHERE name = '{}'".format(name))
