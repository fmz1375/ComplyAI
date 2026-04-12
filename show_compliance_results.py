import sqlite3
import json

conn = sqlite3.connect("project.db")
cursor = conn.cursor()

cursor.execute("SELECT id, document_id, user_id, results_json, pdf_path, created_at FROM compliance_results")
rows = cursor.fetchall()

if not rows:
    print("No records found in compliance_results.")
else:
    for row in rows:
        print(f"ID: {row[0]}")
        print(f"Document ID: {row[1]}")
        print(f"User ID: {row[2]}")
        print(f"Results JSON: {json.dumps(json.loads(row[3]), indent=2) if row[3] else 'None'}")
        print(f"PDF Path: {row[4]}")
        print(f"Created At: {row[5]}")
        print("-" * 40)

conn.close()
