import sqlite3

conn = sqlite3.connect('spam_filter.db')
cursor = conn.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message TEXT NOT NULL,
    hf_label TEXT NOT NULL,
    hf_confidence REAL NOT NULL,
    openai_label TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
''')

conn.commit()
conn.close()

print("✅ Database initialized with Hugging Face + OpenAI columns")
