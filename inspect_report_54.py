import sqlite3, json, os

db_path = os.environ.get('PROJECT_DB_PATH', 'project.db')
if not os.path.exists(db_path):
    print('NO_DB at', os.path.abspath(db_path))
    raise SystemExit(1)
con = sqlite3.connect(db_path)
con.row_factory = sqlite3.Row
cur = con.cursor()
rid = 54
row = cur.execute('SELECT id, questionnaire_answers, metadata, compliance_summary, gap_analysis FROM report WHERE id = ?', (rid,)).fetchone()
if not row:
    print('NO_ROW for id', rid)
else:
    def show(name, v):
        print('---', name, '---')
        if v is None:
            print('NULL')
            return
        try:
            s = v if isinstance(v, str) else v.decode('utf-8')
        except Exception:
            s = str(v)
        print('LEN:', len(s))
        try:
            parsed = json.loads(s)
            print('JSON keys/sample:', list(parsed.keys())[:10] if isinstance(parsed, dict) else (parsed[:3] if isinstance(parsed, list) else type(parsed)))
        except Exception:
            print('RAW:', s[:1000])

    print('ID:', row['id'])
    show('questionnaire_answers', row['questionnaire_answers'])
    show('metadata', row['metadata'])
    show('compliance_summary', row['compliance_summary'])
    show('gap_analysis', row['gap_analysis'])
con.close()