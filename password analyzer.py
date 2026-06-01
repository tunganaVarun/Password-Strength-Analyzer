import re
import hashlib
import secrets
import string
import sqlite3
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class StrengthLevel(Enum):
    """Password strength categories."""
    VERY_WEAK = 0
    WEAK = 1
    FAIR = 2
    STRONG = 3
    VERY_STRONG = 4


@dataclass
class PasswordAnalysis:
    """Results of password strength analysis."""
    password: str
    strength: StrengthLevel
    score: int  # 0-100
    length: int
    has_lowercase: bool
    has_uppercase: bool
    has_digits: bool
    has_special: bool
    has_repeated_chars: bool
    has_sequential_chars: bool
    is_common_password: bool
    feedback: list[str]
    suggestions: list[str]


class PasswordDatabase:
    """SQLite database for tracking password history and preventing reuse."""
    
    def __init__(self, db_path: str = "passwords.db"):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        """Initialize the database schema."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS password_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(user_id, password_hash)
                )
            """)
            conn.commit()
    
    def _hash_password(self, password: str, user_id: str) -> str:
        """
        Hash password with user_id as salt using SHA-256.
        
        Note: In production, use a proper password hashing algorithm
        like bcrypt, scrypt, or Argon2 with unique salts.
        """
        salted = f"{user_id}:{password}".encode()
        return hashlib.sha256(salted).hexdigest()
    
    def is_password_used(self, user_id: str, password: str, history_limit: int = 10) -> bool:
        """Check if password was recently used by this user."""
        password_hash = self._hash_password(password, user_id)
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT 1 FROM password_history 
                WHERE user_id = ? AND password_hash = ?
                ORDER BY created_at DESC
                LIMIT ?
            """, (user_id, password_hash, history_limit))
            return cursor.fetchone() is not None
    
    def store_password(self, user_id: str, password: str):
        """Store password hash in history."""
        password_hash = self._hash_password(password, user_id)
        
        with sqlite3.connect(self.db_path) as conn:
            try:
                conn.execute("""
                    INSERT INTO password_history (user_id, password_hash)
                    VALUES (?, ?)
                """, (user_id, password_hash))
                conn.commit()
            except sqlite3.IntegrityError:
                pass  # Password already in history
    
    def clear_history(self, user_id: str):
        """Clear password history for a user."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM password_history WHERE user_id = ?", (user_id,))
            conn.commit()


class PasswordStrengthAnalyzer:
    """Analyzes password strength and suggests improvements."""
    
    # Common passwords to check against (abbreviated list - expand in production)
    COMMON_PASSWORDS = {
        "password", "123456", "12345678", "qwerty", "abc123", "monkey", "1234567",
        "letmein", "trustno1", "dragon", "baseball", "iloveyou", "master", "sunshine",
        "ashley", "bailey", "shadow", "123123", "654321", "superman", "qazwsx",
        "michael", "football", "password1", "password123", "welcome", "jesus",
        "ninja", "mustang", "password1!", "admin", "admin123", "root", "toor",
        "pass", "test", "guest", "master", "changeme", "hello", "charlie"
    }
    
    # Sequential patterns to detect
    SEQUENTIAL_PATTERNS = [
        "0123456789",
        "9876543210",
        "abcdefghijklmnopqrstuvwxyz",
        "zyxwvutsrqponmlkjihgfedcba",
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm",
    ]
    
    def __init__(self, db_path: str | None = None):
        """Initialize analyzer with optional database for history tracking."""
        self.db = PasswordDatabase(db_path) if db_path else None
    
    def analyze(self, password: str, user_id: str | None = None) -> PasswordAnalysis:
        """
        Perform comprehensive password strength analysis.
        
        Args:
            password: The password to analyze
            user_id: Optional user ID for checking password history
            
        Returns:
            PasswordAnalysis with detailed results
        """
        feedback = []
        suggestions = []
        score = 0
        
        # --- Length Analysis ---
        length = len(password)
        if length < 8:
            feedback.append("Password is too short (minimum 8 characters)")
        elif length < 12:
            feedback.append("Consider using at least 12 characters")
            score += 15
        elif length < 16:
            score += 25
        else:
            score += 35
        
        # --- Character Class Analysis ---
        has_lowercase = bool(re.search(r'[a-z]', password))
        has_uppercase = bool(re.search(r'[A-Z]', password))
        has_digits = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:\'",.<>?/\\`~]', password))
        
        char_classes = sum([has_lowercase, has_uppercase, has_digits, has_special])
        
        if not has_lowercase:
            feedback.append("Add lowercase letters")
        else:
            score += 10
            
        if not has_uppercase:
            feedback.append("Add uppercase letters")
        else:
            score += 10
            
        if not has_digits:
            feedback.append("Add numbers")
        else:
            score += 10
            
        if not has_special:
            feedback.append("Add special characters (!@#$%^&*)")
        else:
            score += 15
        
        # --- Pattern Detection ---
        has_repeated = self._has_repeated_chars(password)
        if has_repeated:
            feedback.append("Avoid repeated characters (e.g., 'aaa', '111')")
            score -= 10
        
        has_sequential = self._has_sequential_chars(password)
        if has_sequential:
            feedback.append("Avoid sequential patterns (e.g., '123', 'abc')")
            score -= 10
        
        # --- Common Password Check ---
        is_common = password.lower() in self.COMMON_PASSWORDS
        if is_common:
            feedback.append("This is a commonly used password - avoid it!")
            score -= 30
        
        # --- Keyboard Pattern Detection ---
        if self._has_keyboard_pattern(password):
            feedback.append("Avoid keyboard patterns (e.g., 'qwerty', 'asdf')")
            score -= 10
        
        # --- Password History Check ---
        if self.db and user_id:
            if self.db.is_password_used(user_id, password):
                feedback.append("This password was used recently - choose a new one")
                score -= 20
        
        # --- Calculate Final Score and Strength ---
        score = max(0, min(100, score))
        strength = self._score_to_strength(score)
        
        # --- Generate Suggestions ---
        suggestions = self._generate_suggestions(password, length, char_classes)
        
        return PasswordAnalysis(
            password="*" * len(password),  # Don't store actual password
            strength=strength,
            score=score,
            length=length,
            has_lowercase=has_lowercase,
            has_uppercase=has_uppercase,
            has_digits=has_digits,
            has_special=has_special,
            has_repeated_chars=has_repeated,
            has_sequential_chars=has_sequential,
            is_common_password=is_common,
            feedback=feedback,
            suggestions=suggestions
        )
    
    def _has_repeated_chars(self, password: str, threshold: int = 3) -> bool:
        """Check for repeated characters."""
        for i in range(len(password) - threshold + 1):
            if len(set(password[i:i + threshold])) == 1:
                return True
        return False
    
    def _has_sequential_chars(self, password: str, threshold: int = 3) -> bool:
        """Check for sequential characters."""
        lower_password = password.lower()
        for pattern in self.SEQUENTIAL_PATTERNS:
            for i in range(len(pattern) - threshold + 1):
                if pattern[i:i + threshold] in lower_password:
                    return True
        return False
    
    def _has_keyboard_pattern(self, password: str) -> bool:
        """Check for common keyboard patterns."""
        keyboard_patterns = ['qwerty', 'asdf', 'zxcv', 'qazwsx', 'wsxedc']
        lower_password = password.lower()
        return any(pattern in lower_password for pattern in keyboard_patterns)
    
    def _score_to_strength(self, score: int) -> StrengthLevel:
        """Convert numeric score to strength level."""
        if score < 20:
            return StrengthLevel.VERY_WEAK
        elif score < 40:
            return StrengthLevel.WEAK
        elif score < 60:
            return StrengthLevel.FAIR
        elif score < 80:
            return StrengthLevel.STRONG
        else:
            return StrengthLevel.VERY_STRONG
    
    def _generate_suggestions(self, password: str, length: int, char_classes: int) -> list[str]:
        """Generate stronger password alternatives."""
        suggestions = []
        
        # Generate passphrase suggestion
        suggestions.append(self.generate_passphrase())
        
        # Generate random strong password
        suggestions.append(self.generate_strong_password())
        
        # Generate memorable pattern-based password
        suggestions.append(self.generate_memorable_password())
        
        return suggestions
    
    @staticmethod
    def generate_strong_password(length: int = 16) -> str:
        """Generate a cryptographically secure random password."""
        # Ensure at least one of each character type
        password = [
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.digits),
            secrets.choice("!@#$%^&*()_+-=[]{}|;:,.<>?")
        ]
        
        # Fill remaining length with random characters
        all_chars = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
        password.extend(secrets.choice(all_chars) for _ in range(length - 4))
        
        # Shuffle to avoid predictable positions
        password_list = list(password)
        secrets.SystemRandom().shuffle(password_list)
        
        return ''.join(password_list)
    
    @staticmethod
    def generate_passphrase(word_count: int = 4) -> str:
        """Generate a memorable passphrase using random words."""
        # Word list (abbreviated - use a larger list like EFF's in production)
        words = [
            "correct", "horse", "battery", "staple", "cloud", "mountain",
            "river", "forest", "thunder", "crystal", "shadow", "phoenix",
            "garden", "silver", "dragon", "castle", "sunrise", "ocean",
            "whisper", "journey", "harmony", "mystery", "ancient", "cosmic",
            "velvet", "meadow", "cascade", "eclipse", "nebula", "prism"
        ]
        
        selected_words = [secrets.choice(words) for _ in range(word_count)]
        # Add a random number and special char for extra security
        separator = secrets.choice(["-", "_", "."])
        passphrase = separator.join(selected_words)
        passphrase += str(secrets.randbelow(100))
        passphrase += secrets.choice("!@#$%^&*")
        
        return passphrase
    
    @staticmethod
    def generate_memorable_password() -> str:
        """Generate a memorable password using a pattern."""
        adjectives = ["Happy", "Swift", "Brave", "Quiet", "Bright"]
        nouns = ["Tiger", "Eagle", "River", "Storm", "Star"]
        
        adj = secrets.choice(adjectives)
        noun = secrets.choice(nouns)
        number = str(secrets.randbelow(900) + 100)  # 100-999
        special = secrets.choice("!@#$%^&*")
        
        return f"{adj}{noun}{number}{special}"


def display_analysis(analysis: PasswordAnalysis):
    """Pretty print the password analysis results."""
    strength_colors = {
        StrengthLevel.VERY_WEAK: "🔴",
        StrengthLevel.WEAK: "🟠", 
        StrengthLevel.FAIR: "🟡",
        StrengthLevel.STRONG: "🟢",
        StrengthLevel.VERY_STRONG: "💚"
    }
    
    print("\n" + "=" * 50)
    print("PASSWORD STRENGTH ANALYSIS")
    print("=" * 50)
    
    print(f"\n{strength_colors[analysis.strength]} Strength: {analysis.strength.name}")
    print(f"📊 Score: {analysis.score}/100")
    print(f"📏 Length: {analysis.length} characters")
    
    print("\n--- Character Analysis ---")
    print(f"  {'✅' if analysis.has_lowercase else '❌'} Lowercase letters")
    print(f"  {'✅' if analysis.has_uppercase else '❌'} Uppercase letters")
    print(f"  {'✅' if analysis.has_digits else '❌'} Numbers")
    print(f"  {'✅' if analysis.has_special else '❌'} Special characters")
    
    print("\n--- Pattern Analysis ---")
    print(f"  {'❌' if analysis.has_repeated_chars else '✅'} No repeated characters")
    print(f"  {'❌' if analysis.has_sequential_chars else '✅'} No sequential patterns")
    print(f"  {'❌' if analysis.is_common_password else '✅'} Not a common password")
    
    if analysis.feedback:
        print("\n--- Feedback ---")
        for item in analysis.feedback:
            print(f"  ⚠️  {item}")
    
    if analysis.suggestions:
        print("\n--- Suggested Stronger Passwords ---")
        for i, suggestion in enumerate(analysis.suggestions, 1):
            print(f"  {i}. {suggestion}")
    
    print("\n" + "=" * 50)


def main():
    """Interactive password strength analyzer."""
    print("\n🔐 PASSWORD STRENGTH ANALYZER 🔐")
    print("-" * 35)
    
    # Initialize with database for history tracking
    analyzer = PasswordStrengthAnalyzer(db_path="password_history.db")
    
    while True:
        print("\nOptions:")
        print("1. Analyze a password")
        print("2. Generate strong passwords")
        print("3. Exit")
        
        choice = input("\nSelect option (1-3): ").strip()
        
        if choice == "1":
            password = input("Enter password to analyze: ")
            user_id = input("Enter user ID (optional, press Enter to skip): ").strip()
            
            analysis = analyzer.analyze(password, user_id if user_id else None)
            display_analysis(analysis)
            
            # Optionally store the password in history
            if user_id and analysis.strength.value >= StrengthLevel.FAIR.value:
                store = input("\nStore this password in history? (y/n): ").strip().lower()
                if store == 'y':
                    analyzer.db.store_password(user_id, password)
                    print("✅ Password stored in history")
        
        elif choice == "2":
            print("\n--- Generated Strong Passwords ---")
            print(f"1. Random (16 chars): {analyzer.generate_strong_password()}")
            print(f"2. Passphrase:        {analyzer.generate_passphrase()}")
            print(f"3. Memorable:         {analyzer.generate_memorable_password()}")
        
        elif choice == "3":
            print("\nGoodbye! Stay secure! 🔒")
            break
        
        else:
            print("Invalid option. Please try again.")


if __name__ == "__main__":
    main()
