import sqlite3
import json

conn = sqlite3.connect("project.db")
cursor = conn.cursor()

cursor.execute("SELECT results_json FROM compliance_results LIMIT 1;")
rows = cursor.fetchall()


conn.close()