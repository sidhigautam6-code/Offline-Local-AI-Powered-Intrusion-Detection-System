import psycopg2
from psycopg2 import sql

def setup_database():
    # Connect to default postgres database
    conn = psycopg2.connect(
        host="localhost",
        database="postgres",
        user="postgres",
        password="your_password"  # Change this
    )
    conn.autocommit = True
    cursor = conn.cursor()
    
    # Create database
    cursor.execute("SELECT 1 FROM pg_database WHERE datname = 'ids_platform'")
    if not cursor.fetchone():
        cursor.execute("CREATE DATABASE ids_db")
        print("✅ Database 'ids_db' created")
    else:
        print("ℹ️ Database 'ids_db' already exists")
    
    cursor.close()
    conn.close()
    
    # Connect to new database and create tables
    conn = psycopg2.connect(
        host="localhost",
        database="ids_platform",
        user="postgres",
        password="your_password"  # Change this
    )
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            email VARCHAR(100) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            full_name VARCHAR(100),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            is_active BOOLEAN DEFAULT TRUE,
            role VARCHAR(20) DEFAULT 'user'
        )
    """)
    
    # Create sessions table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_sessions (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            session_token VARCHAR(255) UNIQUE NOT NULL,
            login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip_address VARCHAR(45)
        )
    """)
    
    # Create activity log table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_activity (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            action VARCHAR(100),
            details TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Insert admin user (password: Admin@123)
    cursor.execute("""
        INSERT INTO users (username, email, password_hash, full_name, role) 
        VALUES ('admin', 'admin@idsplatform.com', 
                '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.VTtYcY0ZqJZq2W', 
                'System Admin', 'admin')
        ON CONFLICT (username) DO NOTHING
    """)
    
    conn.commit()
    cursor.close()
    conn.close()
    print("✅ Tables created successfully")
    print("📝 Admin credentials: username='admin', password='Admin@123'")

if __name__ == "__main__":
    setup_database()