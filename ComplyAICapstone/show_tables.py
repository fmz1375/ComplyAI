import sqlite3

conn = sqlite3.connect("project.db")
cursor = conn.cursor()

cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = cursor.fetchall()

if not tables:
    print("No tables found in project.db.")
else:
    print("Tables in project.db:")
    for t in tables:
        print("-", t[0])

conn.close()
