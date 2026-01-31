# 🔒 Multi-Model Spam Filter with Risk Assessment

An intelligent spam detection system that combines machine learning models with security feature extraction and explainable risk scoring.

##   Features

- **Dual-Model Classification**
  - Hugging Face BERT for fast, local classification (content-based)
  - OpenAI GPT-4 for context-aware analysis (content + metadata)
  - Cost-optimized with confidence thresholds

- **Security Feature Extraction**
  - Stajano-Wilson scam principle detection (authority, urgency, action, loss, plausibility)
  - Header/metadata vulnerability analysis (punycode, display-name mismatch, lookalike domains)
  - Message-level threat indicators (suspicious schemes, URL obfuscation, credential themes)

- **Explainable Risk Scoring**
  - 0-100 risk score based on multiple factors
  - Three-tier risk levels (LOW/MEDIUM/HIGH)
  - Transparent scoring methodology

- **Comprehensive Analysis**
  - Model agreement/disagreement tracking
  - Performance metrics vs ground truth
  - Detailed audit trail in SQLite database

---

##   System Architecture

### 1. Database Setup (`setup_db.py`)

Initializes SQLite database and manages schema migrations:
- Model classification outputs
- Ground truth labels (intended + human-verified)
- Security features (scam signals, header flags, vulnerability indicators)
- Sender metadata (email, display name, domain, reply-to)
- Risk assessment scores

**Usage:**
```bash
python setup_db.py
```

### 2. Email Generation & Classification (`spam_filter.py`)

The main processing pipeline:

1. **Sample Generation**: Creates synthetic emails with ground truth labels
   - Benign workplace emails
   - Phishing emails with evasion techniques (obfuscation, typos, social engineering)

2. **Feature Extraction**: Identifies security indicators
   - Scam signals (authority, urgency, etc.)
   - Header flags (domain mismatches, punycode)
   - Vulnerability flags (suspicious schemes, credential themes)

3. **Classification**: Multi-model approach with full context
   - Hugging Face BERT (message content only - model limitation)
   - OpenAI GPT-4 (message + sender email + display name + reply-to + domain analysis)
   - OpenAI only called if HF confidence < 99.5% (cost optimization)

4. **Risk Scoring**: Explainable 0-100 score
   - Feature-based: scam signals, header flags, vuln flags
   - Model-based: disagreements, consensus spam detection

5. **Persistence**: Stores all data in SQLite for analysis

**Usage:**
```bash
python spam_filter.py
```

### 3. Analysis & Reporting (`query_db.py`)

Generates analyst-friendly reports with:
- Recent message history (rich formatting)
- Model disagreement highlighting
- Performance metrics vs intended labels
- Summary statistics
  - Agreement/disagreement rates
  - OpenAI API usage
  - Risk level distribution
  - Model accuracy

**Usage:**
```bash
python query_db.py
```

---

##   Quick Start

### Prerequisites

- Python 3.8+
- OpenAI API key (set as environment variable or in code)

### Installation

1. **Create a virtual environment** (recommended)

```bash
python -m venv .venv

# Windows
.\.venv\Scripts\Activate.ps1

# macOS / Linux
source .venv/bin/activate
```

2. **Install dependencies**

```bash
pip install transformers torch openai sqlite3
```

3. **Set OpenAI API key**

```bash
# Linux/macOS
export OPENAI_API_KEY="your-key-here"

# Windows (PowerShell)
$env:OPENAI_API_KEY="your-key-here"

# Or edit spam_filter.py directly
```

### Running the System

```bash
# Step 1: Initialize database
python setup_db.py

# Step 2: Process emails
python spam_filter.py

# Step 3: View analysis
python query_db.py
```

---

## 📊 Sample Output

### `spam_filter.py` Output

```
🔒 SPAM FILTER ANALYSIS
================================================================================

  Generating email samples...
✓ Generated 24 samples (21 phishing, 3 benign)

  Processing emails...

[1/24]
────────────────────────────────────────────────────────────────────────────────
  From: Marco Rossi <colleague@company.com>

  Ground Truth: BENIGN

🤖 Classifications:
   HF:     HAM (confidence: 99.8%)
   OpenAI: HAM ⊘ (skipped)
   ✅ Agreement: YES

  Features:
   Scam signals: none
   Security flags: none

🟢 Risk: LOW (0/100)
────────────────────────────────────────────────────────────────────────────────
```

### `query_db.py` Output

```
================================================================================
                        🔒 SPAM FILTER ANALYSIS REPORT
================================================================================

🕵️ Recent Messages
================================================================================
Showing last 10 entries


  Entry #24 | 2025-01-28 14:32:15
────────────────────────────────────────────────────────────────────────────────
  From: Microsoft Security <security@microsoft-auth-alerts.com>
   Domain: microsoft-auth-alerts.com

  Message:
   Urgent: Act now! Your account is locked. Reset your password here.
   hxxps://microsoft-auth[.]example[.]com/session

  Ground Truth:
   Intended: phish

  Detection Features:
   Scam signals: authority, urgency, action, plausibility
   Security flags: display_name_brand_mismatch, domain_has_digits, obfuscated_url

🤖 Model Predictions:
   Hugging Face → SPAM (confidence: 97.3%)
   OpenAI       → SPAM [✓ Called]

🔴 Risk Assessment:
   Level: HIGH
   Score: 82/100

✅ Verdict: AGREEMENT
════════════════════════════════════════════════════════════════════════════════

  Summary Statistics
================================================================================

  Dataset Overview:
   Total messages analyzed: 24
   └─ Intended phishing: 21 (87.5%)
   └─ Intended benign:   3 (12.5%)

  Model Agreement Analysis:
   Total disagreements: 2 (8.3%)
   Avg HF confidence during disagreement: 96.2%

🤖 OpenAI API Usage:
   Messages sent to OpenAI: 18 (75.0%)
   Messages handled by HF only: 6 (25.0%)

⚠️  Risk Level Distribution:
   🟢 LOW: 4 (16.7%)
   🟡 MEDIUM: 8 (33.3%)
   🔴 HIGH: 12 (50.0%)

  Performance Metrics
================================================================================

  Accuracy vs Intended Labels:
   Hugging Face: 91.7%
   OpenAI:       95.8%

   → OpenAI outperforms HF by 4.1 percentage points

================================================================================
                     ✅ Report generated successfully
================================================================================
```

---

##   Configuration

### Confidence Thresholds (`spam_filter.py`)

Adjust when OpenAI is called:

```python
HAM_CONFIDENCE_SKIP = 0.995   # Skip OpenAI if HF is >99.5% confident it's ham
SPAM_CONFIDENCE_SKIP = 0.995  # Skip OpenAI if HF is >99.5% confident it's spam
```

### Risk Scoring Weights

Modify scoring factors in `compute_risk_score()`:

```python
score += 10 * len(scam_signals)    # Scam signal weight
score += 8 * len(header_flags)     # Header flag weight
score += 12 * len(vuln_flags)      # Vulnerability flag weight
score += 25  # Model disagreement penalty
```

### Trusted Domains

Customize for your organization:

```python
TRUSTED_DOMAIN_HINTS = [
    "microsoft", "google", "apple", 
    "yourcompany", "ucl"  # Add your domains here
]
```

---

## 🔍 Feature Detection Details

### Scam Signals (Stajano-Wilson Principles)

- **Authority**: Impersonation of IT support, helpdesk, finance, security teams
- **Urgency**: Time pressure phrases ("urgent", "act now", "immediately")
- **Action**: Requests to click links, login, verify, reset passwords
- **Loss**: Threats of account suspension, mailbox full, overdue payments
- **Plausibility**: Workplace-relevant topics (invoices, calendar, meetings)

### Header Flags

- **Punycode domain**: IDN homograph attacks (xn-- prefix)
- **Reply-To mismatch**: Reply-To domain differs from sender domain
- **Display name brand mismatch**: Brand name in display but untrusted domain
- **Lookalike domains**: Digits in domain, excessive hyphens, typosquatting

### Vulnerability Flags

- **Suspicious schemes**: `file://`, `ms-settings:`, `javascript:`, etc.
- **Obfuscated URLs**: `hxxp://`, `[.]` replacements
- **Credential themes**: Password, 2FA, OTP mentions

---

## 📁 Project Structure

```
spam-filter/
├── setup_db.py          # Database initialization & migrations
├── spam_filter.py       # Main processing pipeline
├── query_db.py          # Analysis & reporting
├── spam_filter.db       # SQLite database (generated)
└── README.md           # This file
```

---

## 🔧 Troubleshooting

### OpenAI API Errors

If you see `⚠️ OpenAI API error`:
- Check your API key is set correctly
- Verify you have API credits
- Check network connectivity

### Database Errors

If `query_db.py` shows database errors:
```bash
# Reinitialize database
python setup_db.py
```

### Model Loading Issues

If Hugging Face models fail to load:
```bash
# Install/update dependencies
pip install --upgrade transformers torch
```

---

##   Future Enhancements

- [ ] Add more sophisticated URL analysis (reputation checks, sandbox)
- [ ] Integrate SPF/DKIM/DMARC validation
- [ ] Add attachment analysis
- [ ] Implement active learning from human feedback
- [ ] Add real-time email monitoring integration
- [ ] Create web dashboard for visualization

---

##   Acknowledgments

- Stajano & Wilson for scam principle research
- Hugging Face for the BERT spam classifier
- OpenAI for GPT-4 API
