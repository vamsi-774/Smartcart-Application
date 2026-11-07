import sqlite3

conn = sqlite3.connect("notes.db")

with open("schema.sql", "r") as f:
    conn.executescript(f.read())

print("Database and tables created successfully!")
conn.close()