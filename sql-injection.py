import sqlite3

def create_table():
    conn = sqlite3.connect("example.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT
        )
    """)
    conn.commit()
    conn.close()

def insert_user(username, password):
    conn = sqlite3.connect("example.db")
    cursor = conn.cursor()
    cursor.execute(f"INSERT INTO users (username, password) VALUES ('{username}', '{password}')")
    conn.commit()
    conn.close()

def login(username, password):
    conn = sqlite3.connect("example.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    print("Executing query:", query)  # デバッグ用出力
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    return user

# テーブル作成
create_table()

# 脆弱なログイン処理の例
username_input = input("Username: ")
password_input = input("Password: ")

user = login(username_input, password_input)
if user:
    print("Login successful! Welcome,", user[1])
else:
    print("Login failed!")
