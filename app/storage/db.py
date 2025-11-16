"""
MySQL-based user storage with salted SHA-256 password hashing.
Handles user registration and authentication.
"""

import os
import secrets
import hashlib
import mysql.connector
from typing import Optional, Tuple
from dotenv import load_dotenv

load_dotenv()


class UserDatabase:
    """Manages user credentials in MySQL with salted password hashing."""
    
    def __init__(self):
        """Initialize database connection."""
        self.config = {
            'host': os.getenv('DB_HOST', 'localhost'),
            'port': int(os.getenv('DB_PORT', 3306)),
            'user': os.getenv('DB_USER', 'scuser'),
            'password': os.getenv('DB_PASSWORD', 'scpass'),
            'database': os.getenv('DB_NAME', 'securechat'),
        }
        self.connection = None
    
    def connect(self):
        """Establish database connection."""
        try:
            self.connection = mysql.connector.connect(**self.config)
            print(f"[✓] Connected to MySQL database: {self.config['database']}")
            return True
        except mysql.connector.Error as e:
            print(f"[✗] Database connection failed: {e}")
            return False
    
    def disconnect(self):
        """Close database connection."""
        if self.connection and self.connection.is_connected():
            self.connection.close()
            print("[✓] Database connection closed")
    
    def initialize_schema(self):
        """Create the users table if it doesn't exist."""
        if not self.connection:
            raise RuntimeError("Database not connected")
        
        cursor = self.connection.cursor()
        
        # Create users table
        create_table_query = """
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            username VARCHAR(255) UNIQUE NOT NULL,
            salt VARBINARY(16) NOT NULL,
            pwd_hash CHAR(64) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_email (email),
            INDEX idx_username (username)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        
        try:
            cursor.execute(create_table_query)
            self.connection.commit()
            print("[✓] Users table initialized successfully")
        except mysql.connector.Error as e:
            print(f"[✗] Failed to create table: {e}")
            raise
        finally:
            cursor.close()
    
    def register_user(self, email: str, username: str, password: str) -> Tuple[bool, str]:
        """
        Register a new user with salted password hashing.
        
        Args:
            email: User's email address
            username: Unique username
            password: Plain text password (will be hashed)
        
        Returns:
            (success: bool, message: str)
        """
        if not self.connection:
            return False, "Database not connected"
        
        # Check if user already exists
        if self.user_exists(email=email):
            return False, "Email already registered"
        
        if self.user_exists(username=username):
            return False, "Username already taken"
        
        # Generate random 16-byte salt
        salt = secrets.token_bytes(16)
        
        # Compute salted hash: SHA256(salt || password)
        pwd_hash = hashlib.sha256(salt + password.encode('utf-8')).hexdigest()
        
        # Insert into database
        cursor = self.connection.cursor()
        insert_query = """
        INSERT INTO users (email, username, salt, pwd_hash)
        VALUES (%s, %s, %s, %s)
        """
        
        try:
            cursor.execute(insert_query, (email, username, salt, pwd_hash))
            self.connection.commit()
            print(f"[✓] User registered: {username} ({email})")
            return True, "Registration successful"
        except mysql.connector.Error as e:
            self.connection.rollback()
            print(f"[✗] Registration failed: {e}")
            return False, f"Database error: {e}"
        finally:
            cursor.close()
    
    def authenticate_user(self, email: str, password: str) -> Tuple[bool, Optional[str]]:
        """
        Authenticate user with email and password.
        
        Args:
            email: User's email address
            password: Plain text password to verify
        
        Returns:
            (authenticated: bool, username: Optional[str])
        """
        if not self.connection:
            return False, None
        
        cursor = self.connection.cursor()
        query = "SELECT username, salt, pwd_hash FROM users WHERE email = %s"
        
        try:
            cursor.execute(query, (email,))
            result = cursor.fetchone()
            
            if not result:
                print(f"[✗] Authentication failed: User not found ({email})")
                return False, None
            
            username, salt, stored_hash = result
            
            # Recompute hash with provided password
            computed_hash = hashlib.sha256(salt + password.encode('utf-8')).hexdigest()
            
            # Constant-time comparison to prevent timing attacks
            if secrets.compare_digest(computed_hash, stored_hash):
                print(f"[✓] Authentication successful: {username}")
                return True, username
            else:
                print(f"[✗] Authentication failed: Invalid password ({email})")
                return False, None
                
        except mysql.connector.Error as e:
            print(f"[✗] Authentication error: {e}")
            return False, None
        finally:
            cursor.close()
    
    def user_exists(self, email: Optional[str] = None, username: Optional[str] = None) -> bool:
        """
        Check if a user exists by email or username.
        
        Args:
            email: Email to check
            username: Username to check
        
        Returns:
            True if user exists, False otherwise
        """
        if not self.connection:
            return False
        
        if not email and not username:
            return False
        
        cursor = self.connection.cursor()
        
        if email:
            query = "SELECT COUNT(*) FROM users WHERE email = %s"
            param = (email,)
        else:
            query = "SELECT COUNT(*) FROM users WHERE username = %s"
            param = (username,)
        
        try:
            cursor.execute(query, param)
            count = cursor.fetchone()[0]
            return count > 0
        except mysql.connector.Error as e:
            print(f"[✗] Error checking user existence: {e}")
            return False
        finally:
            cursor.close()
    
    def get_user_count(self) -> int:
        """Get total number of registered users."""
        if not self.connection:
            return 0
        
        cursor = self.connection.cursor()
        try:
            cursor.execute("SELECT COUNT(*) FROM users")
            count = cursor.fetchone()[0]
            return count
        except mysql.connector.Error as e:
            print(f"[✗] Error getting user count: {e}")
            return 0
        finally:
            cursor.close()


# CLI interface for database management
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="SecureChat Database Manager")
    parser.add_argument("--init", action="store_true", help="Initialize database schema")
    parser.add_argument("--count", action="store_true", help="Show user count")
    
    args = parser.parse_args()
    
    db = UserDatabase()
    
    if not db.connect():
        print("[✗] Failed to connect to database. Check your .env configuration.")
        exit(1)
    
    if args.init:
        print("[*] Initializing database schema...")
        db.initialize_schema()
    
    if args.count:
        count = db.get_user_count()
        print(f"[*] Total registered users: {count}")
    
    if not args.init and not args.count:
        print("Usage: python -m app.storage.db --init")
        print("       python -m app.storage.db --count")
    
    db.disconnect()