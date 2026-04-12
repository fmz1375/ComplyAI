import os
import sqlite3
import json

# Connect to the database
db_path = os.environ.get('PROJECT_DB_PATH', 'project.db')
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

# Query the report table for id=42
row = cursor.execute("SELECT id, compliance_summary, gap_analysis FROM report WHERE id = ?", (42,)).fetchone()

if row:
    print("Report found!")
    print(f"ID: {row['id']}")
    print(f"Compliance Summary type: {type(row['compliance_summary'])}")
    print(f"Compliance Summary: {row['compliance_summary'][:300] if row['compliance_summary'] else 'None'}")
    print(f"\nGap Analysis exists: {bool(row['gap_analysis'])}")
else:
    print("Report not found with id=42")
    
# List all reports to see what ids exist
print("\n\nAll reports in DB (last 10):")
all_reports = cursor.execute("SELECT id, organization_name, created_at FROM report ORDER BY id DESC LIMIT 10").fetchall()
for rep in all_reports:
    print(f"  ID: {rep['id']}, Org: {rep['organization_name']}, Created: {rep['created_at']}")

conn.close()
