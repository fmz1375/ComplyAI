import sqlite3

conn = sqlite3.connect('project.db')

# Add Review column to documents table
try:
    conn.execute('ALTER TABLE documents ADD COLUMN Review TEXT')
    print('Review column added to documents table')
except sqlite3.OperationalError as e:
    if 'duplicate column' in str(e).lower():
        print('Review column already exists')
    else:
        raise e

# Update all existing rows to "Under Review"
conn.execute("UPDATE documents SET Review = 'Under Review' WHERE Review IS NULL OR Review = ''")
conn.commit()
print('All existing documents set to Under Review')

# Verify
cursor = conn.execute('PRAGMA table_info(documents)')
print('\nUpdated documents table schema:')
for row in cursor.fetchall():
    print(row)

# Show current data
cursor = conn.execute('SELECT id, documentTitle, Review FROM documents')
print('\nCurrent documents:')
for row in cursor.fetchall():
    print(row)

conn.close()
