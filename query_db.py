"""
Database Query & Analysis Tool for Spam Filter System

This script provides an analyst-friendly view of classified messages with:
- Recent message history with rich formatting
- Model disagreement highlighting
- Performance metrics and summary statistics
"""

import sqlite3
import textwrap
from typing import List, Tuple, Optional
from datetime import datetime

# Constants
DB_PATH = "spam_filter.db"
DISPLAY_WIDTH = 100


class AnalysisReport:
    """Generates formatted analysis reports from the spam filter database."""
    
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self.conn = None
        self.cursor = None
    
    def __enter__(self):
        """Context manager entry."""
        self.conn = sqlite3.connect(self.db_path)
        self.cursor = self.conn.cursor()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with proper cleanup."""
        if self.conn:
            self.conn.close()
    
    @staticmethod
    def wrap_text(text: str, width: int = DISPLAY_WIDTH, indent: str = "") -> str:
        """Wrap text to specified width with optional indentation."""
        if not text:
            return "(none)"
        wrapped = textwrap.fill(text, width=width, initial_indent=indent, subsequent_indent=indent)
        return wrapped
    
    @staticmethod
    def parse_csv_flags(csv_text: str) -> List[str]:
        """Parse comma-separated flags into a list."""
        if not csv_text:
            return []
        return [x.strip() for x in csv_text.split(",") if x.strip()]
    
    @staticmethod
    def format_timestamp(ts: str) -> str:
        """Format timestamp for display."""
        try:
            dt = datetime.fromisoformat(ts)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except:
            return ts
    
    def print_header(self, title: str, emoji: str = "📊"):
        """Print a formatted section header."""
        print(f"\n{emoji} {title}")
        print("=" * DISPLAY_WIDTH)
    
    def print_divider(self, char: str = "-"):
        """Print a divider line."""
        print(char * DISPLAY_WIDTH)
    
    def display_message_entry(self, row: Tuple):
        """Display a single message entry in analyst-friendly format."""
        (
            id_, sender_name, sender_email, reply_to, sender_domain,
            msg, true_intended, true_human, scam_signals_csv, flags_csv,
            hf_label, hf_conf, openai_norm, used_openai,
            risk_score, risk_level, ts
        ) = row
        
        # Parse flags
        scam_signals = self.parse_csv_flags(scam_signals_csv)
        flags = self.parse_csv_flags(flags_csv)
        
        # Check for model disagreement
        models_agree = True
        if hf_label in ("spam", "ham") and openai_norm in ("spam", "ham"):
            models_agree = (hf_label == openai_norm)
        
        verdict_emoji = "✅" if models_agree else "⚠️"
        verdict_text = " AGREEMENT" if models_agree else " DISAGREEMENT"
        
        # Risk level color coding
        risk_emoji = {
            "LOW": "🟢",
            "MEDIUM": "🟡",
            "HIGH": "🔴"
        }.get(risk_level, "⚪")
        
        # Print entry
        print(f"\n  Entry #{id_} | {self.format_timestamp(ts)}")
        print(self.print_divider("─"))
        
        # Sender information
        print(f"  From: {sender_name or '(no name)'} <{sender_email or 'unknown'}>")
        print(f"   Domain: {sender_domain or 'unknown'}")
        if reply_to:
            print(f"   Reply-To: {reply_to}")
        
        # Message content
        print(f"\n  Message:")
        print(self.wrap_text(msg, indent="   "))
        
        # Ground truth
        print(f"\n  Ground Truth:")
        print(f"   Intended: {true_intended or 'unknown'}")
        if true_human:
            print(f"   Human verified: {true_human}")
        
        # Detection features
        print(f"\n  Detection Features:")
        print(f"   Scam signals: {', '.join(scam_signals) if scam_signals else 'none detected'}")
        print(f"   Security flags: {', '.join(flags) if flags else 'none detected'}")
        
        # Model predictions
        print(f"\n🤖 Model Predictions:")
        print(f"   Hugging Face → {hf_label.upper()} (confidence: {hf_conf:.1%})")
        openai_status = "✓ Called" if used_openai else "⊘ Skipped (threshold)"
        print(f"   OpenAI       → {str(openai_norm).upper()} [{openai_status}]")
        
        # Risk assessment
        print(f"\n{risk_emoji} Risk Assessment:")
        print(f"   Level: {risk_level or 'UNKNOWN'}")
        print(f"   Score: {risk_score if risk_score is not None else 'N/A'}/100")
        
        # Verdict
        print(f"\n{verdict_emoji} Verdict: {verdict_text}")
        
        self.print_divider("═")
    
    def display_recent_messages(self, limit: int = 10):
        """Display recent messages with full details."""
        self.print_header("Recent Messages", "🕵️")
        print(f"Showing last {limit} entries\n")
        
        query = """
            SELECT
                id,
                sender_display_name, sender_email, reply_to, sender_domain,
                message,
                true_label_intended, true_label_human,
                scam_signals,
                header_flags,
                hf_label, hf_confidence,
                COALESCE(openai_label_norm, openai_label) AS openai_norm,
                used_openai,
                risk_score, risk_level,
                created_at
            FROM messages
            ORDER BY created_at DESC
            LIMIT ?
        """
        
        rows = self.cursor.execute(query, (limit,)).fetchall()
        
        if not rows:
            print("⚠️  No messages found in database")
            return
        
        for row in rows:
            self.display_message_entry(row)
    
    def display_summary_statistics(self):
        """Display summary statistics and insights."""
        self.print_header("Summary Statistics")
        
        # Total messages
        self.cursor.execute("SELECT COUNT(*) FROM messages")
        total = self.cursor.fetchone()[0]
        
        if total == 0:
            print("\n⚠️  No data available yet")
            return
        
        # Intended labels breakdown
        self.cursor.execute("""
            SELECT
                SUM(CASE WHEN true_label_intended='phish' THEN 1 ELSE 0 END),
                SUM(CASE WHEN true_label_intended='benign' THEN 1 ELSE 0 END)
            FROM messages
        """)
        phish_cnt, benign_cnt = self.cursor.fetchone()
        
        print(f"\n  Dataset Overview:")
        print(f"   Total messages analyzed: {total}")
        print(f"   └─ Intended phishing: {phish_cnt} ({phish_cnt/total*100:.1f}%)")
        print(f"   └─ Intended benign:   {benign_cnt} ({benign_cnt/total*100:.1f}%)")
        
        # Model disagreements
        self.cursor.execute("""
            SELECT COUNT(*)
            FROM messages
            WHERE hf_label IN ('spam','ham')
              AND COALESCE(openai_label_norm, openai_label) IN ('spam','ham')
              AND hf_label != COALESCE(openai_label_norm, openai_label)
        """)
        disagreements = self.cursor.fetchone()[0]
        
        # Average confidence when disagreeing
        self.cursor.execute("""
            SELECT AVG(hf_confidence)
            FROM messages
            WHERE hf_label IN ('spam','ham')
              AND COALESCE(openai_label_norm, openai_label) IN ('spam','ham')
              AND hf_label != COALESCE(openai_label_norm, openai_label)
        """)
        avg_conf_disagree = self.cursor.fetchone()[0]
        
        print(f"\n  Model Agreement Analysis:")
        print(f"   Total disagreements: {disagreements} ({disagreements/total*100:.1f}%)")
        if avg_conf_disagree is not None:
            print(f"   Avg HF confidence during disagreement: {avg_conf_disagree:.1%}")
        
        # OpenAI usage
        self.cursor.execute("SELECT COUNT(*) FROM messages WHERE used_openai = 1")
        openai_calls = self.cursor.fetchone()[0]
        
        print(f"\n🤖 OpenAI API Usage:")
        print(f"   Messages sent to OpenAI: {openai_calls} ({openai_calls/total*100:.1f}%)")
        print(f"   Messages handled by HF only: {total - openai_calls} ({(total-openai_calls)/total*100:.1f}%)")
        
        # Risk level distribution
        self.cursor.execute("""
            SELECT risk_level, COUNT(*) 
            FROM messages 
            WHERE risk_level IS NOT NULL 
            GROUP BY risk_level
        """)
        risk_dist = self.cursor.fetchall()
        
        if risk_dist:
            print(f"\n⚠️  Risk Level Distribution:")
            risk_emojis = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🔴"}
            for level, count in sorted(risk_dist, key=lambda x: {"LOW": 0, "MEDIUM": 1, "HIGH": 2}.get(x[0], 3)):
                emoji = risk_emojis.get(level, "⚪")
                print(f"   {emoji} {level}: {count} ({count/total*100:.1f}%)")
    
    def display_performance_metrics(self):
        """Display model performance against ground truth."""
        self.print_header("Performance Metrics", "🎯")
        
        query = """
            SELECT
                SUM(CASE WHEN hf_label = true_label_intended THEN 1 ELSE 0 END) * 1.0 / COUNT(*) AS hf_acc,
                SUM(CASE WHEN COALESCE(openai_label_norm, openai_label) = true_label_intended THEN 1 ELSE 0 END) * 1.0 / COUNT(*) AS openai_acc
            FROM messages
            WHERE true_label_intended IN ('phish','benign')
              AND hf_label IN ('spam','ham')
              AND COALESCE(openai_label_norm, openai_label) IN ('spam','ham')
        """
        
        result = self.cursor.execute(query).fetchone()
        
        if result and result[0] is not None and result[1] is not None:
            hf_acc, openai_acc = result
            print(f"\n  Accuracy vs Intended Labels:")
            print(f"   Hugging Face: {hf_acc*100:.1f}%")
            print(f"   OpenAI:       {openai_acc*100:.1f}%")
            
            if openai_acc > hf_acc:
                diff = (openai_acc - hf_acc) * 100
                print(f"\n   → OpenAI outperforms HF by {diff:.1f} percentage points")
            elif hf_acc > openai_acc:
                diff = (hf_acc - openai_acc) * 100
                print(f"\n   → Hugging Face outperforms OpenAI by {diff:.1f} percentage points")
            else:
                print(f"\n   → Models perform equally")
        else:
            print("\n⚠️  Insufficient data to compute accuracy metrics")
    
    def generate_full_report(self, recent_limit: int = 10):
        """Generate a complete analysis report."""
        print("\n" + "=" * DISPLAY_WIDTH)
        print("  SPAM FILTER ANALYSIS REPORT".center(DISPLAY_WIDTH))
        print("=" * DISPLAY_WIDTH)
        
        self.display_recent_messages(recent_limit)
        self.display_summary_statistics()
        self.display_performance_metrics()
        
        print("\n" + "=" * DISPLAY_WIDTH)
        print("  Report generated successfully".center(DISPLAY_WIDTH))
        print("=" * DISPLAY_WIDTH + "\n")


def main():
    """Main entry point for database analysis."""
    try:
        with AnalysisReport() as report:
            report.generate_full_report(recent_limit=10)
    except sqlite3.OperationalError as e:
        print(f"\n❌ Database error: {e}")
        print("💡 Hint: Run setup_db.py first to initialize the database")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        raise


if __name__ == "__main__":
    main()
