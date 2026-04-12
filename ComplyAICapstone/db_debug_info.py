import sqlite3
from security_utils import SQLInjectionDefense

conn = sqlite3.connect('project.db')
cursor = conn.cursor()

# Show all tables
print('Tables:')
cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
for row in cursor.fetchall():
    print(row[0])

# Show schema for key tables
tables = ['documents', 'compliance', 'compliance_results', 'users']
for table in tables:
    print(f'\nSchema for {table}:')
    try:
        table = SQLInjectionDefense.validate_table_name(table)
        cursor.execute(f'PRAGMA table_info({table})')
        for col in cursor.fetchall():
            print(col)
    except ValueError as e:
        print(f'Error: {e}')
    except Exception as e:
        print(f'Error: {e}')

# Show a sample row from each table
for table in tables:
    print(f'\nSample row from {table}:')
    try:
        table = SQLInjectionDefense.validate_table_name(table)
        cursor.execute(f'SELECT * FROM {table} LIMIT 1')
        row = cursor.fetchone()
        print(row)
    except ValueError as e:
        print(f'Error: {e}')
    except Exception as e:
        print(f'Error: {e}')

conn.close()
