import sqlite3
import json

conn = sqlite3.connect("project.db")
cursor = conn.cursor()

# Get all table names
cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = [t[0] for t in cursor.fetchall()]

if not tables:
    print("No tables found in project.db.")
else:
    for table in tables:
        print(f"\n===== {table} =====")
        try:
            cursor.execute(f"SELECT * FROM {table}")
            rows = cursor.fetchall()
            col_names = [description[0] for description in cursor.description]
            if not rows:
                print("(No rows)")
            else:
                for row in rows:
                    row_dict = dict(zip(col_names, row))
                    # Pretty print JSON fields if present
                    for k, v in row_dict.items():
                        if isinstance(v, str):
                            try:
                                parsed = json.loads(v)
                                row_dict[k] = json.dumps(parsed, indent=2)
                            except Exception:
                                pass
                    print(row_dict)
        except Exception as e:
            print(f"Error reading table {table}: {e}")

conn.close()
