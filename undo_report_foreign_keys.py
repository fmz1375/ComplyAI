import sqlite3

conn = sqlite3.connect('project.db')
cursor = conn.cursor()

# 1. Create old report table without foreign keys
cursor.execute('''
CREATE TABLE IF NOT EXISTS report_old (
    id INTEGER PRIMARY KEY,
    document_id INTEGER,
    user_id INTEGER,
    compliance_summary TEXT,
    gap_analysis TEXT,
    risk_assessment TEXT,
    risk_heat_map TEXT,
    recommendations TEXT,
    created_at TEXT
)
''')

# 2. Copy data from current report table
cursor.execute('''
INSERT INTO report_old (id, document_id, user_id, compliance_summary, gap_analysis, risk_assessment, risk_heat_map, recommendations, created_at)
SELECT id, document_id, user_id, compliance_summary, gap_analysis, risk_assessment, risk_heat_map, recommendations, created_at FROM report
''')

# 3. Drop current report table
cursor.execute('DROP TABLE report')

# 4. Rename old table to report
cursor.execute('ALTER TABLE report_old RENAME TO report')

conn.commit()
conn.close()
print('Undo complete: report table reverted to original structure without foreign keys.')
