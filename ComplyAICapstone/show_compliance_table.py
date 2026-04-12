import sqlite3

DB_PATH = "project.db"

def show_compliance_table():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute("PRAGMA table_info(compliance)")
        columns = cursor.fetchall()
        if not columns:
            print("No compliance table found.")
            return
        print("Columns in compliance table:")
        for col in columns:
            print(f"- {col[1]} (type: {col[2]})")

        cursor.execute("SELECT * FROM compliance")
        rows = cursor.fetchall()
        if not rows:
            print("No data in compliance table.")
            return
        print("\nData in compliance table:")
        col_names = [col[1] for col in columns]
        for row in rows:
            row_dict = dict(zip(col_names, row))
            print(row_dict)
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    show_compliance_table()