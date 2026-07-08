import psycopg2

print("Testing PostgreSQL connection...")
print("="*50)

# Try to connect
try:
    conn = psycopg2.connect(
        host="localhost",
        database="ids_db",
        user="postgres",
        password="postgres",  # Change this to your password
        port="5432"
    )
    print("✅ Successfully connected to PostgreSQL!")
    
    # Test query
    cursor = conn.cursor()
    cursor.execute("SELECT version();")
    version = cursor.fetchone()
    print(f"✅ PostgreSQL Version: {version[0][:50]}...")
    
    # Check if users table exists
    cursor.execute("""
        SELECT EXISTS (
            SELECT FROM information_schema.tables 
            WHERE table_name = 'users'
        );
    """)
    table_exists = cursor.fetchone()[0]
    
    if table_exists:
        print("✅ Users table exists")
        # Count users
        cursor.execute("SELECT COUNT(*) FROM users;")
        count = cursor.fetchone()[0]
        print(f"✅ Total users: {count}")
    else:
        print("❌ Users table does not exist! Run database setup first.")
    
    cursor.close()
    conn.close()
    print("="*50)
    print("✅ All tests passed!")
    
except psycopg2.OperationalError as e:
    print(f"❌ Connection failed: {e}")
    print("\nPossible solutions:")
    print("1. PostgreSQL service is not running")
    print("2. Wrong password in the connection string")
    print("3. Database 'ids_platform' doesn't exist")
    print("4. PostgreSQL is not installed correctly")