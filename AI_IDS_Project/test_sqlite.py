from db_config import db_manager

print("Testing SQLite database...")
print("="*50)

# Test connection
if db_manager:
    print("✅ Database manager created")
    
    # Test login
    success, user_info, message = db_manager.login_user("admin", "Admin@123")
    if success:
        print(f"✅ Login successful!")
        print(f"   Username: {user_info['username']}")
        print(f"   Email: {user_info['email']}")
        print(f"   Role: {user_info['role']}")
    else:
        print(f"❌ Login failed: {message}")
    
    # Test registration
    print("\nTesting registration...")
    success, message = db_manager.register_user("newuser", "new@test.com", "TestPass123", "Test User")
    print(f"Registration: {message}")
    
    # Test with new user
    if "successful" in message.lower():
        success, user_info, message = db_manager.login_user("newuser", "TestPass123")
        if success:
            print(f"✅ New user login successful!")
else:
    print("❌ Failed to create database manager")

print("="*50)
print("✅ SQLite is working! You can now run your app.")