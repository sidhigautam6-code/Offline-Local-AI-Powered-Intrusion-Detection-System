from db_config import db_manager

# Test connection
if db_manager.connection_pool:
    print("✅ Database connected successfully!")
    
    # Test registration
    success, msg = db_manager.register_user("testuser", "test@example.com", "TestPass123", "Test User")
    print(f"Registration: {msg}")
    
    # Test login
    success, user_info, msg = db_manager.login_user("testuser", "TestPass123")
    print(f"Login: {msg}")
    if success:
        print(f"Welcome {user_info['username']}!")
else:
    print("❌ Database connection failed")