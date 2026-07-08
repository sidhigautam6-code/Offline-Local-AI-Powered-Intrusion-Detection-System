-- =====================================================
-- COMPLETE DATABASE SETUP FOR AI-IDS PLATFORM
-- =====================================================

-- Drop existing tables if they exist (to avoid conflicts)
DROP TABLE IF EXISTS user_activity CASCADE;
DROP TABLE IF EXISTS user_sessions CASCADE;
DROP TABLE IF EXISTS users CASCADE;

-- Create users table with all required columns
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    role VARCHAR(20) DEFAULT 'user'
);

-- Create session table for tracking active sessions
CREATE TABLE user_sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    session_token VARCHAR(255) UNIQUE NOT NULL,
    login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(45)
);

-- Create user activity log table
CREATE TABLE user_activity (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    action VARCHAR(100),
    details TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for better performance
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_sessions_token ON user_sessions(session_token);

-- Insert an admin user (password: Admin@123)
INSERT INTO users (username, email, password_hash, full_name, role) 
VALUES ('admin', 'admin@idsdb.com', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.VTtYcY0ZqJZq2W', 'System Admin', 'admin')
ON CONFLICT (username) DO NOTHING;

-- Insert a test user (password: Test@123)
INSERT INTO users (username, email, password_hash, full_name, role) 
VALUES ('testuser', 'test@example.com', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.VTtYcY0ZqJZq2W', 'Test User', 'user')
ON CONFLICT (username) DO NOTHING;

-- Display success message
DO $$ 
BEGIN
    RAISE NOTICE '✅ Database setup completed successfully!';
    RAISE NOTICE '📝 Admin credentials: username="admin", password="Admin@123"';
    RAISE NOTICE '📝 Test user credentials: username="testuser", password="Test@123"';
END $$;

-- Verify the tables were created correctly
SELECT 'Users table columns:' as Info;
SELECT column_name, data_type 
FROM information_schema.columns 
WHERE table_name = 'users' 
ORDER BY ordinal_position;