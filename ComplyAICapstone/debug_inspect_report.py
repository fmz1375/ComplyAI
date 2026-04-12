import sqlite3, json, os

db_path = os.environ.get('PROJECT_DB_PATH', 'project.db')
if not os.path.exists(db_path):
    print('NO_DB')
    raise SystemExit
con = sqlite3.connect(db_path)
con.row_factory = sqlite3.Row
cur = con.cursor()
row = cur.execute('SELECT id, questionnaire_answers, metadata, compliance_summary, gap_analysis FROM report ORDER BY id DESC LIMIT 1').fetchone()
if not row:
    print('NO_ROWS')
else:
    def short(x):
        if x is None:
            return 'NULL'
        try:
            if isinstance(x, (bytes, bytearray)):
                x = x.decode('utf-8', errors='replace')
        except Exception:
            pass
        s = str(x)
        return (s[:1000] + '...') if len(s) > 1000 else s
    print('id=', row['id'])
    print('--- questionnaire_answers ---')
    print(short(row['questionnaire_answers']))
    print('--- metadata ---')
    print(short(row['metadata']))
    print('--- compliance_summary ---')
    print(short(row['compliance_summary']))
    print('--- gap_analysis ---')
    print(short(row['gap_analysis']))
con.close()