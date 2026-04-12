import sqlite3

conn = sqlite3.connect('project.db')
cursor = conn.cursor()

# 1. Create new table with foreign keys
cursor.execute('''
CREATE TABLE IF NOT EXISTS report_new (
    id INTEGER PRIMARY KEY,
    document_id INTEGER,
    user_id INTEGER,
    compliance_summary TEXT,
    gap_analysis TEXT,
    risk_assessment TEXT,
    risk_heat_map TEXT,
    recommendations TEXT,
    created_at TEXT,
    FOREIGN KEY(document_id) REFERENCES documents(id),
    FOREIGN KEY(user_id) REFERENCES users(id)
)
''')

# 2. Copy data from old report table
cursor.execute('''
INSERT INTO report_new (id, document_id, user_id, compliance_summary, gap_analysis, risk_assessment, risk_heat_map, recommendations, created_at)
SELECT id, document_id, user_id, compliance_summary, gap_analysis, risk_assessment, risk_heat_map, recommendations, created_at FROM report
''')

# 3. Drop old report table
cursor.execute('DROP TABLE report')

# 4. Rename new table to report
cursor.execute('ALTER TABLE report_new RENAME TO report')

conn.commit()
conn.close()
print('Migration complete: report table now has foreign keys for document_id and user_id.')
