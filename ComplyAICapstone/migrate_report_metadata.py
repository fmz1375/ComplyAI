import sqlite3

conn = sqlite3.connect('project.db')
cursor = conn.cursor()

# Add new columns for organization metadata to report table
cursor.execute('ALTER TABLE report ADD COLUMN organization_name TEXT')
cursor.execute('ALTER TABLE report ADD COLUMN industry TEXT')
cursor.execute('ALTER TABLE report ADD COLUMN size TEXT')
cursor.execute('ALTER TABLE report ADD COLUMN scope TEXT')

conn.commit()
conn.close()
print('Migration complete: organization metadata columns added to report table.')
