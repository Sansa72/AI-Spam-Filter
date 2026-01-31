"""
Database Setup Script for Spam Filter System

This script initializes the SQLite database and manages schema migrations.
It creates the base messages table and safely adds new columns as the system evolves.
"""

import sqlite3
from typing import Set

# Constants
DB_PATH = "spam_filter.db"


class DatabaseManager:
    """Manages database initialization and schema migrations."""
    
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
    
    def get_existing_columns(self) -> Set[str]:
        """Retrieve set of existing column names from the messages table."""
        self.cursor.execute("PRAGMA table_info(messages);")
        return {row[1] for row in self.cursor.fetchall()}
    
    def add_column_if_missing(self, col_name: str, col_def: str, existing_cols: Set[str]) -> bool:
        """
        Add a column to the messages table if it doesn't already exist.
        
        Args:
            col_name: Name of the column to add
            col_def: SQL definition of the column (type and constraints)
            existing_cols: Set of existing column names
            
        Returns:
            True if column was added, False if it already existed
        """
        if col_name not in existing_cols:
            self.cursor.execute(f"ALTER TABLE messages ADD COLUMN {col_name} {col_def};")
            return True
        return False
    
    def create_base_table(self):
        """Create the base messages table if it doesn't exist."""
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message TEXT NOT NULL,
                hf_label TEXT NOT NULL,
                hf_confidence REAL NOT NULL,
                openai_label TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
    
    def migrate_schema(self):
        """Add new columns for enhanced features if they don't exist."""
        existing_cols = self.get_existing_columns()
        added_columns = []
        
        # Schema definition: (column_name, column_definition, description)
        new_columns = [
            # OpenAI classification fields
            ("openai_label_norm", "TEXT", "Normalized OpenAI label (spam/ham)"),
            ("openai_label_raw", "TEXT", "Raw OpenAI response"),
            ("used_openai", "INTEGER DEFAULT 1", "Whether OpenAI was called (1) or skipped (0)"),
            
            # Ground truth labels
            ("true_label_intended", "TEXT", "Intended label from generator (phish/benign)"),
            ("true_label_human", "TEXT", "Optional manual label (phish/benign/ambiguous)"),
            
            # Scam detection features
            ("scam_signals", "TEXT", "Stajano-Wilson-style scam signals (CSV)"),
            
            # Sender metadata
            ("sender_email", "TEXT", "Sender email address"),
            ("sender_display_name", "TEXT", "Sender display name"),
            ("reply_to", "TEXT", "Reply-To address if different from sender"),
            ("sender_domain", "TEXT", "Extracted sender domain"),
            
            # Security indicators
            ("header_flags", "TEXT", "Metadata and vulnerability flags (CSV)"),
            
            # Risk assessment
            ("risk_score", "INTEGER", "Computed risk score (0-100)"),
            ("risk_level", "TEXT", "Risk level category (LOW/MEDIUM/HIGH)"),
        ]
        
        for col_name, col_def, description in new_columns:
            if self.add_column_if_missing(col_name, col_def, existing_cols):
                added_columns.append(f"  • {col_name}: {description}")
        
        return added_columns
    
    def initialize(self):
        """Initialize the database with base table and migrations."""
        print("🔧 Initializing spam filter database...")
        print(f"Database: {self.db_path}\n")
        
        # Create base table
        self.create_base_table()
        print("✓ Base table created/verified")
        
        # Run migrations
        added_columns = self.migrate_schema()
        
        if added_columns:
            print(f"\nAdded {len(added_columns)} new columns:")
            for col in added_columns:
                print(col)
        else:
            print("\n✓ Schema is up to date (no migrations needed)")
        
        # Commit changes
        self.conn.commit()
        print("\nDatabase initialization complete!")


def main():
    """Main entry point for database setup."""
    try:
        with DatabaseManager() as db:
            db.initialize()
    except Exception as e:
        print(f"\nError initializing database: {e}")
        raise


if __name__ == "__main__":
    main()
