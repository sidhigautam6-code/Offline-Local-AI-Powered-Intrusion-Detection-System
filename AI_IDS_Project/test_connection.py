from db_config import db_manager

print("Testing database connection...")

# Check if db_manager exists
if db_manager:
    print("✅ db_manager imported successfully")
    
    # Check connection pool
    if db_manager.connection_pool:
        print("✅ Database connection pool created")
        
        # Test login
        success, user_info, message = db_manager.login_user("admin", "Admin@123")
        if success:
            print(f"✅ Login successful! Welcome {user_info['username']}")
        else:
            print(f"❌ Login failed: {message}")
    else:
        print("❌ Failed to create connection pool")
else:
    print("❌ Failed to import db_manager")