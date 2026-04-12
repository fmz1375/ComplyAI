import sqlite3
from security_utils import SQLInjectionDefense

conn = sqlite3.connect('project.db')
cursor = conn.cursor()

# Clear all rows from compliance_results
table = 'compliance_results'
try:
    table = SQLInjectionDefense.validate_table_name(table)
    cursor.execute(f'DELETE FROM {table}')
    conn.commit()
    print(f'All rows deleted from {table}.')
except Exception as e:
    print(f'Error: {e}')

conn.close()
