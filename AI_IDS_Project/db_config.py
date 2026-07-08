import sqlite3
import bcrypt
import secrets
from datetime import datetime
import os

class DatabaseManager:
    def __init__(self):
        self.db_file = "ids_db.db"
        self.create_database()
    
    def create_database(self):
        """Create SQLite database and tables"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # Create users table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    full_name TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1,
                    role TEXT DEFAULT 'user'
                )
            ''')
            
            # Create sessions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    session_token TEXT UNIQUE NOT NULL,
                    login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    ip_address TEXT,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
            # Create activity log table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_activity (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    action TEXT,
                    details TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
            # Check if admin user exists
            cursor.execute("SELECT * FROM users WHERE username = 'admin'")
            if not cursor.fetchone():
                # Insert admin user (password: Admin@123)
                admin_password = self.hash_password("Admin@123")
                cursor.execute('''
                    INSERT INTO users (username, email, password_hash, full_name, role) 
                    VALUES (?, ?, ?, ?, ?)
                ''', ('admin', 'admin@idsdb.com', admin_password, 'System Admin', 'admin'))
            
            # Check if test user exists
            cursor.execute("SELECT * FROM users WHERE username = 'testuser'")
            if not cursor.fetchone():
                # Insert test user (password: Test@123)
                test_password = self.hash_password("Test@123")
                cursor.execute('''
                    INSERT INTO users (username, email, password_hash, full_name, role) 
                    VALUES (?, ?, ?, ?, ?)
                ''', ('testuser', 'test@example.com', test_password, 'Test User', 'user'))
            
            conn.commit()
            conn.close()
            print("✅ SQLite database created successfully!")
            return True
            
        except Exception as e:
            print(f"❌ Database creation error: {e}")
            return False
    
    def get_connection(self):
        """Get database connection"""
        try:
            conn = sqlite3.connect(self.db_file)
            conn.row_factory = sqlite3.Row
            return conn
        except Exception as e:
            print(f"Connection error: {e}")
            return None
    
    def hash_password(self, password):
        """Hash password using bcrypt"""
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    def verify_password(self, password, hashed):
        """Verify password"""
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    
    def register_user(self, username, email, password, full_name=None):
        """Register a new user"""
        conn = self.get_connection()
        if not conn:
            return False, "Database connection failed"
        
        try:
            cursor = conn.cursor()
            password_hash = self.hash_password(password)
            
            # Check if username or email exists
            cursor.execute(
                "SELECT id FROM users WHERE username = ? OR email = ?",
                (username, email)
            )
            if cursor.fetchone():
                return False, "Username or email already exists"
            
            # Insert new user
            cursor.execute('''
                INSERT INTO users (username, email, password_hash, full_name) 
                VALUES (?, ?, ?, ?)
            ''', (username, email, password_hash, full_name))
            
            user_id = cursor.lastrowid
            conn.commit()
            
            # Log activity
            self.log_user_activity(user_id, "User Registration", f"User {username} registered")
            
            return True, "Registration successful! Please login."
        except Exception as e:
            return False, f"Registration error: {str(e)}"
        finally:
            conn.close()
    
    def login_user(self, username, password, ip_address=None):
        """Authenticate user and create session"""
        conn = self.get_connection()
        if not conn:
            return False, None, "Database connection failed"
        
        try:
            cursor = conn.cursor()
            
            # Get user by username or email
            cursor.execute('''
                SELECT id, username, email, password_hash, role, is_active 
                FROM users WHERE username = ? OR email = ?
            ''', (username, username))
            
            user = cursor.fetchone()
            
            if not user:
                return False, None, "Invalid credentials"
            
            user_id = user[0]
            db_username = user[1]
            email = user[2]
            password_hash = user[3]
            role = user[4]
            is_active = user[5]
            
            if not is_active:
                return False, None, "Account is deactivated"
            
            if not self.verify_password(password, password_hash):
                return False, None, "Invalid credentials"
            
            # Generate session token
            session_token = secrets.token_urlsafe(32)
            
            # Update last login
            cursor.execute(
                "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
                (user_id,)
            )
            
            # Create session
            cursor.execute('''
                INSERT INTO user_sessions (user_id, session_token, ip_address) 
                VALUES (?, ?, ?)
            ''', (user_id, session_token, ip_address))
            
            conn.commit()
            
            # Log login activity
            self.log_user_activity(user_id, "User Login", f"User {db_username} logged in")
            
            return True, {
                'user_id': user_id,
                'username': db_username,
                'email': email,
                'role': role,
                'session_token': session_token
            }, "Login successful"
            
        except Exception as e:
            return False, None, f"Login error: {str(e)}"
        finally:
            conn.close()
    
    def logout_user(self, session_token):
        """Logout user by removing session"""
        conn = self.get_connection()
        if not conn:
            return False
        
        try:
            cursor = conn.cursor()
            
            # Get user_id before deleting session
            cursor.execute(
                "SELECT user_id FROM user_sessions WHERE session_token = ?",
                (session_token,)
            )
            result = cursor.fetchone()
            
            if result:
                user_id = result[0]
                # Delete session
                cursor.execute(
                    "DELETE FROM user_sessions WHERE session_token = ?",
                    (session_token,)
                )
                conn.commit()
                
                # Log logout activity
                self.log_user_activity(user_id, "User Logout", "User logged out")
            
            return True
        except Exception as e:
            return False
        finally:
            conn.close()
    
    def validate_session(self, session_token):
        """Validate if session token is still active"""
        conn = self.get_connection()
        if not conn:
            return None
        
        try:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT u.id, u.username, u.email, u.role, u.is_active, s.session_token 
                FROM users u 
                JOIN user_sessions s ON u.id = s.user_id 
                WHERE s.session_token = ? 
                AND datetime(s.login_time) > datetime('now', '-24 hours')
            ''', (session_token,))
            
            user = cursor.fetchone()
            
            if user and user[4]:  # is_active is True
                return {
                    'user_id': user[0],
                    'username': user[1],
                    'email': user[2],
                    'role': user[3],
                    'session_token': user[5]
                }
            return None
        except Exception as e:
            return None
        finally:
            conn.close()
    
    def log_user_activity(self, user_id, action, details):
        """Log user activity"""
        conn = self.get_connection()
        if not conn:
            return
        
        try:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO user_activity (user_id, action, details) 
                VALUES (?, ?, ?)
            ''', (user_id, action, details))
            conn.commit()
        except Exception as e:
            pass
        finally:
            conn.close()
    
    def change_password(self, user_id, old_password, new_password):
        """Change user password"""
        conn = self.get_connection()
        if not conn:
            return False, "Database connection failed"
        
        try:
            cursor = conn.cursor()
            
            # Get current password hash
            cursor.execute(
                "SELECT password_hash FROM users WHERE id = ?",
                (user_id,)
            )
            result = cursor.fetchone()
            
            if not result or not self.verify_password(old_password, result[0]):
                return False, "Current password is incorrect"
            
            # Update password
            new_hash = self.hash_password(new_password)
            cursor.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (new_hash, user_id)
            )
            conn.commit()
            
            # Log activity
            self.log_user_activity(user_id, "Password Change", "User changed password")
            
            return True, "Password changed successfully"
        except Exception as e:
            return False, f"Error changing password: {str(e)}"
        finally:
            conn.close()

# Create a global instance
db_manager = DatabaseManager()