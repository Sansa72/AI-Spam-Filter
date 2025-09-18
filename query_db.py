import sqlite3

conn = sqlite3.connect("spam_filter.db")
cursor = conn.cursor()

print("\n🕵️ Last 10 entries:")
for row in cursor.execute("SELECT * FROM messages ORDER BY created_at DESC LIMIT 10"):
    print(row)

print("\n📊 Count of spam (Hugging Face):")
cursor.execute("SELECT COUNT(*) FROM messages WHERE hf_label = 'spam'")
print(cursor.fetchone()[0])

print("\n⚠️ Disagreements between Hugging Face and OpenAI:")
for row in cursor.execute("SELECT * FROM messages WHERE hf_label != LOWER(openai_label)"):
    print(row)

conn.close()
