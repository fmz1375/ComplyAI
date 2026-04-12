import sqlite3

DB_PATH = "project.db"

def create_report_table():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                document_id INTEGER,
                user_id INTEGER,
                compliance_summary TEXT,
                gap_analysis TEXT,
                risk_assessment TEXT,
                risk_heat_map TEXT,
                recommendations TEXT,
                created_at TEXT,
                framework_name TEXT,
                framework_version_id TEXT,
                framework_version_label TEXT,
                framework_used_at TEXT
            )
        """)
        conn.commit()
        print("report table created or already exists.")
    except Exception as e:
        print(f"Error creating report table: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    create_report_table()