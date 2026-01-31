"""
Multi-Model Spam Filter with Feature Extraction & Risk Scoring

This system generates synthetic email samples, classifies them using multiple models,
extracts security features, and computes risk scores. Results are stored in SQLite
for analysis and model comparison.

Features:
- Dual-model classification (Hugging Face BERT + OpenAI GPT-4)
- Stajano-Wilson scam signal detection
- Header/metadata vulnerability analysis
- Explainable risk scoring (0-100)
- Synthetic adversarial sample generation
"""

import os
import re
import random
import sqlite3
from dataclasses import dataclass
from typing import List, Optional, Tuple

# Suppress tokenizers parallelism warning
os.environ["TOKENIZERS_PARALLELISM"] = "false"

from transformers import pipeline
from openai import OpenAI


# ============================================================================
# CONFIGURATION
# ============================================================================

DB_PATH = "spam_filter.db"

# Sample generation parameters
RANDOM_SEED = 7
VARIANTS_PER_SEED = 6

# Confidence thresholds for OpenAI escalation
# If HF is very confident, skip OpenAI to save API calls
HAM_CONFIDENCE_SKIP = 0.995
SPAM_CONFIDENCE_SKIP = 0.995

# OpenAI configuration
OPENAI_MODEL = "gpt-4o"

# Suspicious URL schemes (indicators only, not blockers)
SUSPICIOUS_SCHEMES = [
    "file://", "search-ms:", "shell:", "ms-settings:", "msdt:",
    "ms-officecmd:", "ms-excel:", "ms-word:", "ms-powerpoint:",
    "javascript:", "data:"
]

# Brand keywords for display-name mismatch detection
BRAND_KEYWORDS = [
    "microsoft", "google", "apple", "it support", 
    "helpdesk", "finance", "accounts"
]

# Trusted domain hints (customize for your organization)
TRUSTED_DOMAIN_HINTS = [
    "microsoft", "google", "apple", "ucl", "yourcompany"
]


# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class EmailItem:
    """Represents an email message with sender metadata and ground truth label."""
    sender_email: str
    sender_display_name: str
    reply_to: Optional[str]
    message: str
    true_label_intended: str  # 'phish' or 'benign'


@dataclass
class ClassificationResult:
    """Stores classification results from both models."""
    hf_label: str
    hf_confidence: float
    openai_norm: str
    openai_raw: Optional[str]
    used_openai: bool


@dataclass
class FeatureSet:
    """Contains extracted security features and metadata."""
    scam_signals: List[str]
    sender_domain: Optional[str]
    header_flags: List[str]
    vuln_flags: List[str]


@dataclass
class RiskAssessment:
    """Risk score and level for an email."""
    score: int  # 0-100
    level: str  # LOW/MEDIUM/HIGH


# ============================================================================
# MODEL INITIALIZATION
# ============================================================================

def initialize_models():
    """Initialize classification models."""
    print("🔧 Initializing models...")
    
    # Hugging Face BERT classifier
    classifier = pipeline(
        "text-classification", 
        model="SGHOSH1999/bert-email-spam-classifier_tuned"
    )
    label_map = {"LABEL_0": "ham", "LABEL_1": "spam"}
    print("✓ Hugging Face BERT loaded")
    
    # OpenAI client
    client = OpenAI(api_key="")  # Replace with your actual API key
    print("✓ OpenAI client initialized")
    
    return classifier, label_map, client


classifier, label_map, client = initialize_models()


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def normalize_openai_label(raw: str) -> str:
    """
    Convert OpenAI output into standardized 'spam' or 'ham' label.
    
    Handles various response formats:
    - "Spam", "spam", "SPAM"
    - "Not Spam", "Not spam", "ham"
    """
    if raw is None:
        return "ham"
    
    text = raw.strip().lower()
    
    # Check for explicit "not spam" first
    if "not spam" in text or "not_spam" in text or "notspam" in text or text == "ham":
        return "ham"
    
    # Then check for spam
    if text == "spam" or ("spam" in text and "not spam" not in text and "notspam" not in text):
        return "spam"
    
    # Default to spam if "spam" appears anywhere
    return "spam" if "spam" in text else "ham"


def extract_domain(email_address: Optional[str]) -> Optional[str]:
    """Extract domain from email address."""
    if not email_address or "@" not in email_address:
        return None
    return email_address.split("@", 1)[1].strip().lower()


# ============================================================================
# FEATURE EXTRACTION
# ============================================================================

def detect_scam_signals(message: str, sender_display_name: str = "") -> List[str]:
    """
    Detect Stajano-Wilson-inspired scam principles in message content.
    
    Signals detected:
    - authority: Impersonation of official roles
    - urgency: Time pressure tactics
    - action: Requests to click/login/verify
    - loss: Threat of negative consequences
    - plausibility: Workplace-relevant topics
    
    Returns:
        List of detected signal names
    """
    msg = (message or "").lower()
    name = (sender_display_name or "").lower()
    signals = []
    
    # Authority (impersonation / official role)
    authority_keywords = [
        "it support", "helpdesk", "security team", "admin", 
        "finance", "accounts"
    ]
    if any(keyword in msg for keyword in authority_keywords):
        signals.append("authority")
    if any(keyword in name for keyword in authority_keywords):
        if "authority" not in signals:
            signals.append("authority")
    
    # Urgency / time pressure
    urgency_keywords = [
        "urgent", "act now", "immediately", "please handle today", 
        "asap", "final notice"
    ]
    if any(keyword in msg for keyword in urgency_keywords):
        signals.append("urgency")
    
    # Action required
    action_keywords = [
        "click", "log in", "login", "reset", "verify", 
        "review", "open the link", "confirm"
    ]
    if any(keyword in msg for keyword in action_keywords):
        signals.append("action")
    if any(proto in msg for proto in ["http://", "https://", "hxxp://", "hxxps://"]):
        if "action" not in signals:
            signals.append("action")
    
    # Loss / consequence framing
    loss_keywords = [
        "account locked", "locked", "suspended", 
        "mailbox is almost full", "payment", "invoice", "overdue"
    ]
    if any(keyword in msg for keyword in loss_keywords):
        signals.append("loss")
    
    # Plausibility (workplace-pretext topics)
    plausibility_keywords = [
        "mailbox", "invoice", "calendar", "meeting", 
        "microsoft", "teams", "sharepoint"
    ]
    if any(keyword in msg for keyword in plausibility_keywords):
        signals.append("plausibility")
    
    return signals


def compute_header_flags(
    sender_email: str, 
    sender_display_name: str, 
    reply_to: Optional[str]
) -> Tuple[Optional[str], List[str]]:
    """
    Analyze email headers for suspicious patterns.
    
    Checks for:
    - Punycode domains (IDN homograph attacks)
    - Reply-To mismatch
    - Display name brand impersonation
    - Lookalike domains (digits, excessive hyphens)
    
    Returns:
        Tuple of (sender_domain, list_of_flags)
    """
    flags = []
    sender_domain = extract_domain(sender_email)
    reply_domain = extract_domain(reply_to) if reply_to else None
    
    # Punycode domain detection
    if sender_domain and sender_domain.startswith("xn--"):
        flags.append("punycode_domain")
    
    # Reply-To mismatch
    if reply_domain and sender_domain and reply_domain != sender_domain:
        flags.append("reply_to_mismatch")
    
    # Display-name brand mismatch
    if sender_display_name and sender_domain:
        name_lower = sender_display_name.lower()
        if any(brand in name_lower for brand in BRAND_KEYWORDS):
            if not any(trusted in sender_domain for trusted in TRUSTED_DOMAIN_HINTS):
                flags.append("display_name_brand_mismatch")
    
    # Lookalike domain patterns
    if sender_domain:
        if any(char.isdigit() for char in sender_domain):
            flags.append("domain_has_digits")
        if sender_domain.count("-") >= 2:
            flags.append("domain_many_hyphens")
        
        # Common typosquatting patterns
        typo_patterns = ["micros0ft", "g00gle", "app1e", "rnicrosoft", "paypa1"]
        if any(pattern in sender_domain for pattern in typo_patterns):
            flags.append("lookalike_domain_pattern")
    
    return sender_domain, flags


def detect_message_vuln_flags(message: str) -> List[str]:
    """
    Detect message-level vulnerability indicators.
    
    Checks for:
    - Suspicious URL schemes (file://, ms-settings:, etc.)
    - URL obfuscation (hxxp, [.])
    - Credential-related themes
    
    Returns:
        List of vulnerability flag names
    """
    text = (message or "").lower()
    flags = []
    
    # Check for suspicious URL schemes
    for scheme in SUSPICIOUS_SCHEMES:
        if scheme in text:
            flags.append(f"scheme:{scheme}")
    
    # URL obfuscation patterns
    if "hxxp://" in text or "hxxps://" in text or "[.]" in text:
        flags.append("obfuscated_url")
    
    # Credential harvesting themes
    credential_keywords = [
        "password", "passw0rd", "credentials", 
        "2fa", "one-time code", "otp"
    ]
    if any(keyword in text for keyword in credential_keywords):
        flags.append("credential_theme")
    
    return flags


# ============================================================================
# CLASSIFICATION
# ============================================================================

def classify_with_hf(
    message: str,
    sender_email: str = "",
    sender_display_name: str = "",
    reply_to: Optional[str] = None
) -> Tuple[str, float]:
    """
    Classify message using Hugging Face BERT model.
    
    Note: Current BERT model only uses message content, but signature
    is kept consistent for potential future models that use metadata.
    
    Args:
        message: Email message content
        sender_email: Sender's email address (currently unused)
        sender_display_name: Display name (currently unused)
        reply_to: Reply-To address (currently unused)
        
    Returns:
        Tuple of (label, confidence_score)
    """
    result = classifier(message)[0]
    label = label_map.get(result["label"], "unknown")
    confidence = float(result["score"])
    return label, confidence


def should_call_openai(hf_label: str, hf_confidence: float) -> bool:
    """
    Determine if OpenAI should be called based on HF confidence.
    
    Skip OpenAI if HF is very confident to save API costs.
    """
    if hf_label == "ham" and hf_confidence >= HAM_CONFIDENCE_SKIP:
        return False
    if hf_label == "spam" and hf_confidence >= SPAM_CONFIDENCE_SKIP:
        return False
    return True


def classify_with_openai(
    message: str,
    sender_email: str,
    sender_display_name: str,
    reply_to: Optional[str],
    sender_domain: Optional[str]
) -> Tuple[str, str]:
    """
    Classify message using OpenAI GPT-4 with full context.
    
    Args:
        message: Email message content
        sender_email: Sender's email address
        sender_display_name: Display name shown to recipient
        reply_to: Reply-To address if different from sender
        sender_domain: Extracted sender domain
        
    Returns:
        Tuple of (normalized_label, raw_response)
    """
    try:
        # Build context-rich prompt
        email_context = f"""From: {sender_display_name} <{sender_email}>
Sender Domain: {sender_domain or 'unknown'}"""
        
        if reply_to:
            email_context += f"\nReply-To: {reply_to}"
        
        email_context += f"\n\nMessage:\n{message}"
        
        response = client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": """You are an expert email security analyst. Analyze emails for phishing and spam, considering:
- Sender domain legitimacy and mismatches
- Display name vs actual email address
- Reply-To header inconsistencies
- Message content and urgency tactics
- Impersonation attempts

Reply with only 'Spam' or 'Not Spam'."""
                },
                {
                    "role": "user",
                    "content": f"Analyze this email for phishing/spam:\n\n{email_context}"
                }
            ],
            max_tokens=10,
            temperature=0
        )
        raw = response.choices[0].message.content.strip()
        normalized = normalize_openai_label(raw)
        return normalized, raw
    except Exception as e:
        print(f"⚠️  OpenAI API error: {e}")
        return "ham", None


# ============================================================================
# RISK SCORING
# ============================================================================

def compute_risk_score(
    hf_label: str,
    hf_conf: float,
    openai_norm: str,
    used_openai: bool,
    scam_signals: List[str],
    header_flags: List[str],
    vuln_flags: List[str]
) -> RiskAssessment:
    """
    Calculate explainable risk score (0-100) based on multiple factors.
    
    Scoring factors:
    - Scam signals: +10 per unique signal
    - Header flags: +8 per flag
    - Vulnerability flags: +12 per flag
    - Model disagreement: +25 (especially if HF was confident)
    - Both models say spam: +10
    
    Returns:
        RiskAssessment with score (0-100) and level (LOW/MEDIUM/HIGH)
    """
    score = 0
    
    # Feature-based scoring
    score += 10 * len(set(scam_signals))
    score += 8 * len(set(header_flags))
    score += 12 * len(set(vuln_flags))
    
    # Model-based scoring
    both_labeled = (hf_label in ("spam", "ham")) and (openai_norm in ("spam", "ham"))
    disagreement = both_labeled and (hf_label != openai_norm)
    
    if disagreement and used_openai:
        score += 25
        # Extra penalty for confident disagreement
        if hf_conf >= 0.98:
            score += 15
    elif both_labeled and hf_label == "spam" and openai_norm == "spam":
        # Both models agree it's spam
        score += 10
    
    # Clamp to 0-100 range
    score = max(0, min(100, score))
    
    # Determine risk level
    if score >= 70:
        level = "HIGH"
    elif score >= 40:
        level = "MEDIUM"
    else:
        level = "LOW"
    
    return RiskAssessment(score=score, level=level)


# ============================================================================
# DATABASE OPERATIONS
# ============================================================================

def save_to_database(
    email: EmailItem,
    classification: ClassificationResult,
    features: FeatureSet,
    risk: RiskAssessment
):
    """Save classification results and features to database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Combine all flags
    all_flags = features.header_flags + features.vuln_flags
    
    cursor.execute(
        """
        INSERT INTO messages (
            message, hf_label, hf_confidence,
            openai_label, openai_label_norm, openai_label_raw, used_openai,
            true_label_intended,
            scam_signals,
            sender_email, sender_display_name, reply_to, sender_domain,
            header_flags,
            risk_score, risk_level
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            email.message,
            classification.hf_label,
            float(classification.hf_confidence),
            classification.openai_raw if classification.openai_raw else classification.openai_norm,
            classification.openai_norm,
            classification.openai_raw,
            int(classification.used_openai),
            email.true_label_intended,
            ",".join(sorted(set(features.scam_signals))) if features.scam_signals else "",
            email.sender_email,
            email.sender_display_name,
            email.reply_to,
            features.sender_domain or "",
            ",".join(sorted(set(all_flags))) if all_flags else "",
            int(risk.score),
            risk.level
        )
    )
    
    conn.commit()
    conn.close()


# ============================================================================
# SAMPLE GENERATION
# ============================================================================

def obfuscate_url(url: str) -> str:
    """Apply common URL obfuscation techniques used in phishing."""
    url = url.replace("http://", "hxxp://").replace("https://", "hxxps://")
    url = url.replace(".", "[.]")
    return url


def inject_typos(text: str) -> str:
    """Inject common evasion typos."""
    text = re.sub(r"account", "acc0unt", text, flags=re.IGNORECASE)
    text = re.sub(r"verify", "ver1fy", text, flags=re.IGNORECASE)
    text = re.sub(r"password", "passw0rd", text, flags=re.IGNORECASE)
    return text


def add_social_engineering_context(text: str) -> str:
    """Add social engineering framing to increase believability."""
    prefixes = [
        "Quick one — ",
        "Sorry to bother you — ",
        "Urgent: ",
        "Heads up: ",
        "FYI — "
    ]
    suffixes = [
        " Sent from iPhone",
        " Thanks.",
        " Please handle today.",
        " Let me know once done.",
        " (auto-generated)"
    ]
    return random.choice(prefixes) + text + random.choice(suffixes)


def generate_email_samples(seed: int = RANDOM_SEED, variants_per_seed: int = VARIANTS_PER_SEED) -> List[EmailItem]:
    """
    Generate synthetic email samples with ground truth labels.
    
    Creates:
    - Benign workplace emails
    - Phishing emails with various evasion techniques
    
    Args:
        seed: Random seed for reproducibility
        variants_per_seed: Number of variants to generate per phishing template
        
    Returns:
        List of EmailItem objects with intended labels
    """
    random.seed(seed)
    samples = []
    
    # Benign samples
    benign_samples = [
        EmailItem(
            sender_email="colleague@company.com",
            sender_display_name="Marco Rossi",
            reply_to=None,
            message="Hey, are we still meeting at 6 PM?",
            true_label_intended="benign"
        ),
        EmailItem(
            sender_email="it-support@company.com",
            sender_display_name="IT Support",
            reply_to=None,
            message="Your mailbox is almost full. Increase storage to keep receiving email.",
            true_label_intended="benign"
        ),
        EmailItem(
            sender_email="accounts@company.com",
            sender_display_name="Accounts Payable",
            reply_to=None,
            message="Can you review this invoice today? The client is waiting.",
            true_label_intended="benign"
        )
    ]
    samples.extend(benign_samples)
    
    # Phishing URLs for testing
    phishing_urls = [
        "https://secure-login.example.com/reset",
        "https://account-verify.example.com",
        "https://invoice-review.example.com/doc",
        "https://microsoft-auth.example.com/session"
    ]
    
    # Phishing templates (more aggressive but still realistic)
    phish_templates = [
        EmailItem(
            sender_email="it-support@company-security.com",
            sender_display_name="IT Support",
            reply_to="helpdesk@company-security.com",
            message="URGENT: Your mailbox is almost full and will be suspended within 24 hours. Click here to increase storage and avoid service interruption.",
            true_label_intended="phish"
        ),
        EmailItem(
            sender_email="accounts@company-payments.com",
            sender_display_name="Finance Team",
            reply_to="payments@company-payments.com",
            message="IMMEDIATE ACTION REQUIRED: Invoice payment overdue. Review and confirm payment details to avoid account suspension.",
            true_label_intended="phish"
        ),
        EmailItem(
            sender_email="security@microsoft-auth-alerts.com",
            sender_display_name="Microsoft Security",
            reply_to=None,
            message="Your account has been locked due to suspicious activity. Verify your identity immediately to restore access.",
            true_label_intended="phish"
        )
    ]
    
    # Generate variants of each phishing template
    for template in phish_templates:
        samples.append(template)
        
        for _ in range(variants_per_seed):
            msg = template.message
            
            # Apply obfuscated URL (85% chance)
            if random.random() < 0.85:
                msg += " " + obfuscate_url(random.choice(phishing_urls))
            
            # Add social engineering framing (65% chance)
            if random.random() < 0.65:
                msg = add_social_engineering_context(msg)
            
            # Add typo-based evasion (55% chance)
            if random.random() < 0.55:
                msg = inject_typos(msg)
            
            # Add impersonation signature (45% chance)
            if random.random() < 0.45 and "it support" not in msg.lower():
                msg += "\n— IT Support"
            
            # Add special scheme indicator (10% chance for detection demos)
            if random.random() < 0.10:
                msg += "\nfile://C:/Users/Public/Document.pdf"
            
            samples.append(
                EmailItem(
                    sender_email=template.sender_email,
                    sender_display_name=template.sender_display_name,
                    reply_to=template.reply_to,
                    message=msg,
                    true_label_intended="phish"
                )
            )
    
    # De-duplicate by (sender_email, message)
    seen = set()
    unique_samples = []
    for email in samples:
        key = (email.sender_email, email.message)
        if key not in seen:
            seen.add(key)
            unique_samples.append(email)
    
    return unique_samples


# ============================================================================
# OUTPUT FORMATTING
# ============================================================================

def print_classification_summary(
    email: EmailItem,
    classification: ClassificationResult,
    features: FeatureSet,
    risk: RiskAssessment
):
    """Print a formatted summary of classification results."""
    # Risk level emoji
    risk_emoji = {
        "LOW": "🟢",
        "MEDIUM": "🟡",
        "HIGH": "🔴"
    }.get(risk.level, "⚪")
    
    # Agreement status
    models_agree = classification.hf_label == classification.openai_norm
    agreement_emoji = "✅" if models_agree else "⚠️"
    
    print("\n" + "─" * 80)
    print(f"  From: {email.sender_display_name} <{email.sender_email}>")
    if email.reply_to:
        print(f"   Reply-To: {email.reply_to}")
    
    print(f"\n  Ground Truth: {email.true_label_intended.upper()}")
    
    print(f"\n  Classifications:")
    print(f"   HF:     {classification.hf_label.upper()} (confidence: {classification.hf_confidence:.1%})")
    openai_status = "✓" if classification.used_openai else "⊘ (skipped)"
    print(f"   OpenAI: {classification.openai_norm.upper()} {openai_status}")
    print(f"   {agreement_emoji} Agreement: {'YES' if models_agree else 'NO'}")
    
    print(f"\n Features:")
    print(f"   Scam signals: {', '.join(features.scam_signals) if features.scam_signals else 'none'}")
    all_flags = features.header_flags + features.vuln_flags
    print(f"   Security flags: {', '.join(all_flags) if all_flags else 'none'}")
    
    print(f"\n{risk_emoji} Risk: {risk.level} ({risk.score}/100)")
    print("─" * 80)


# ============================================================================
# MAIN EXECUTION
# ============================================================================

def process_email(email: EmailItem):
    """Process a single email through the complete pipeline."""
    # Step 1: Extract security features first (needed for OpenAI call)
    scam_signals = detect_scam_signals(email.message, email.sender_display_name)
    sender_domain, header_flags = compute_header_flags(
        email.sender_email, 
        email.sender_display_name, 
        email.reply_to
    )
    vuln_flags = detect_message_vuln_flags(email.message)
    
    features = FeatureSet(
        scam_signals=scam_signals,
        sender_domain=sender_domain,
        header_flags=header_flags,
        vuln_flags=vuln_flags
    )
    
    # Step 2: Classify with Hugging Face
    hf_label, hf_confidence = classify_with_hf(
        email.message,
        email.sender_email,
        email.sender_display_name,
        email.reply_to
    )
    
    # Step 3: Conditionally escalate to OpenAI (with full context)
    used_openai = should_call_openai(hf_label, hf_confidence)
    if used_openai:
        openai_norm, openai_raw = classify_with_openai(
            email.message,
            email.sender_email,
            email.sender_display_name,
            email.reply_to,
            sender_domain
        )
    else:
        openai_norm = hf_label  # Inherit HF decision
        openai_raw = None
    
    classification = ClassificationResult(
        hf_label=hf_label,
        hf_confidence=hf_confidence,
        openai_norm=openai_norm,
        openai_raw=openai_raw,
        used_openai=used_openai
    )
    
    # Step 4: Compute risk score
    risk = compute_risk_score(
        hf_label=hf_label,
        hf_conf=hf_confidence,
        openai_norm=openai_norm,
        used_openai=used_openai,
        scam_signals=scam_signals,
        header_flags=header_flags,
        vuln_flags=vuln_flags
    )
    
    # Step 5: Display results
    print_classification_summary(email, classification, features, risk)
    
    # Step 6: Save to database
    save_to_database(email, classification, features, risk)


def main():
    """Main execution flow."""
    print("\n" + "=" * 80)
    print("  SPAM FILTER ANALYSIS".center(80))
    print("=" * 80)
    
    # Generate synthetic email samples
    print("\n  Generating email samples...")
    emails = generate_email_samples(seed=RANDOM_SEED, variants_per_seed=VARIANTS_PER_SEED)
    print(f"✓ Generated {len(emails)} samples ({sum(1 for e in emails if e.true_label_intended == 'phish')} phishing, {sum(1 for e in emails if e.true_label_intended == 'benign')} benign)")
    
    # Process each email
    print("\n  Processing emails...")
    for i, email in enumerate(emails, 1):
        print(f"\n[{i}/{len(emails)}]", end="")
        process_email(email)
    
    print("\n" + "=" * 80)
    print("✅ Processing complete! Run query_db.py to view detailed analysis.".center(80))
    print("=" * 80 + "\n")


if __name__ == "__main__":
    main()
