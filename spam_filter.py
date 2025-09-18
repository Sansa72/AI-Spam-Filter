from transformers import pipeline
from openai import OpenAI
import sqlite3

# Set up the OpenAI client
client = OpenAI(api_key="API_KEY")  # Replace with your actual API key

def save_to_db(message, hf_label, hf_confidence, openai_label):
    conn = sqlite3.connect("spam_filter.db")
    cursor = conn.cursor()

    cursor.execute('''
        INSERT INTO messages (message, hf_label, hf_confidence, openai_label)
        VALUES (?, ?, ?, ?)
    ''', (message, hf_label, hf_confidence, openai_label))

    conn.commit()
    conn.close()

def openai_check(text):
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": "You are a spam filter."},
            {"role": "user", "content": f"Is this message spam? Reply only with 'Spam' or 'Not Spam':\n\n{text}"}
        ]
    )
    return response.choices[0].message.content.strip()

# Load spam classifier from Hugging Face
classifier = pipeline("text-classification", model="SGHOSH1999/bert-email-spam-classifier_tuned")

messages = [
    "You've won a free iPhone! Click the link to claim.",
    "Hey, are we still meeting at 6 PM?",
    "Act now! Your account is locked. Reset your password here.",
]

label_map = {
    "LABEL_0": "ham",
    "LABEL_1": "spam"
}

for msg in messages:
    result = classifier(msg)[0]
    hf_label = label_map.get(result["label"], "unknown")
    hf_confidence = result["score"]

    openai_label = openai_check(msg)

    print(f"Message: {msg}")
    print(f"Hugging Face says: {hf_label}, Confidence: {hf_confidence:.2f}")
    print(f"OpenAI says: {openai_label}")
    print("-" * 50)

    # Save to database
    save_to_db(msg, hf_label, hf_confidence, openai_label)


