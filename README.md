# Spam Filter (Hugging Face + OpenAI) — Demo Project

A simple end-to-end demo that classifies short messages as **spam** or **ham** using a fine-tuned **Hugging Face** model and an **OpenAI** model, and stores results in a local **SQLite** database. It also includes a small query script to inspect results.

## Features

- **Dual detection**: compares a BERT-based spam classifier from Hugging Face with an OpenAI classification prompt.
- **SQLite persistence**: stores message text, model labels, model confidence, and timestamps.
- **Quick inspection**: view the last few rows, counts, and disagreements between the two models.

## Repo Structure

```
setup_db.py        # Creates/initializes the SQLite DB and `messages` table
spam_filter.py     # Runs both models on sample messages and writes results to DB
query_db.py        # Prints quick stats & disagreements from the DB
spam_filter.db     # Generated SQLite database file (after running)
```

## How It Works

1. **Database initialization** — `setup_db.py` creates a `messages` table with columns for the message text, Hugging Face label & confidence, the OpenAI label, and a timestamp.
2. **Inference & write** — `spam_filter.py` loads a Hugging Face spam classifier, prompts the OpenAI model to answer with **“Spam”** or **“Not Spam”**, then inserts one row per message into SQLite.
3. **Query & inspect** — `query_db.py` prints the last 10 entries, counts of spam, and any cases where the two models disagree.

## Setup

### 1) Create and activate a virtual environment (optional but recommended)

```bash
python -m venv .venv
# Windows (PowerShell)
.\.venv\Scripts\Activate.ps1
# macOS/Linux
source .venv/bin/activate
```

### 2) Install dependencies

```bash
pip install transformers openai sqlite-utils
```

> If you plan to use GPU-accelerated transformers, also install an appropriate PyTorch build for your system.

### 3) Environment variables

Create a `.env` or set an environment variable for your OpenAI key (recommended — **do not hardcode keys in code**):

- **Windows (PowerShell)**
  ```powershell
  setx OPENAI_API_KEY "sk-your-key"
  ```

- **macOS/Linux (bash/zsh)**
  ```bash
  export OPENAI_API_KEY="sk-your-key"
  ```

Then, inside your code you can read it with `os.environ["OPENAI_API_KEY"]`. See the “Hardening & Security” notes below to update the sample.

## Usage

### 1) Initialize the database

```bash
python setup_db.py
```

This creates `spam_filter.db` with a `messages` table if it doesn’t already exist.

### 2) Run the spam filter

```bash
python spam_filter.py
```

This will:
- Load the Hugging Face pipeline model
- Call the OpenAI API with a compact system+user classification prompt
- Print labels from both models
- Insert the results into SQLite

### 3) Query & inspect

```bash
python query_db.py
```

This prints:
- The last 10 entries
- A count of rows labeled **spam** by the HF model
- A list of any rows where the two model labels **disagree**

## Database Schema

`setup_db.py` creates the table:

```sql
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message TEXT NOT NULL,
    hf_label TEXT NOT NULL,
    hf_confidence REAL NOT NULL,
    openai_label TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Example Row

| id | message                                | hf_label | hf_confidence | openai_label | created_at          |
|----|----------------------------------------|----------|---------------|--------------|---------------------|
| 1  | You've won a free iPhone! Click …      | spam     | 0.98          | Spam         | 2025-09-19 12:34:56 |

## Model Details

- **Hugging Face**: `SGHOSH1999/bert-email-spam-classifier_tuned` via `transformers.pipeline("text-classification", ...)`
- **OpenAI**: Chat Completions API with a short system prompt (“You are a spam filter.”) and a user prompt asking for **exactly** “Spam” or “Not Spam”.

> The two outputs are stored side-by-side so you can quickly analyze agreement/disagreement rates.

## Hardening & Security (Recommended Changes)

- **Do not hardcode your OpenAI key**. Read it from `OPENAI_API_KEY`:
  ```python
  import os
  from openai import OpenAI
  client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
  ```
- **Validate OpenAI responses**: normalize responses to `spam` / `ham` (or a fixed enum) to avoid case/format drift.
- **Add try/except** around API calls and DB writes; log failures.
- **Migrations**: if you add columns later, consider a light migration step.
- **Prompt hardening**: Make the classification instruction explicit (e.g., “Reply with exactly `spam` or `ham`”).

## Troubleshooting

- **`openai` or `transformers` import error** — run `pip install -U openai transformers` inside your virtual environment.
- **`no such table: messages`** — run `python setup_db.py` first.
- **OpenAI auth errors** — confirm `OPENAI_API_KEY` is set and visible in your shell (`echo $Env:OPENAI_API_KEY` on Windows PowerShell).
- **Slow HF downloads** — first run will download model weights; subsequent runs are much faster.

## Roadmap Ideas

- Add CLI flags to classify an arbitrary message or a file of messages.
- Track disagreements and export a small CSV for error analysis.
- Add a lightweight API (FastAPI or a Next.js route) for classifying messages via HTTP.
- Build a small Streamlit or web UI to paste text and see both model results.
