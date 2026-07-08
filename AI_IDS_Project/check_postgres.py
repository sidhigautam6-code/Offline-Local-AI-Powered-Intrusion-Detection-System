import psycopg2

print("Testing PostgreSQL connection...")
print("-" * 40)

# Try different passwords
passwords = ["", "postgres", "admin", "password", "root", "1234"]

for pwd in passwords:
    try:
        print(f"Trying password: '{pwd}'")
        conn = psycopg2.connect(
            host="localhost",
            database="ids_db",
            user="postgres",
            password=pwd,
            port="5432",
            connect_timeout=3
        )
        print(f"✅ SUCCESS! Password is: '{pwd}'")
        conn.close()
        break
    except psycopg2.OperationalError as e:
        if "password authentication failed" in str(e):
            print(f"   Wrong password")
        elif "Connection refused" in str(e):
            print(f"   PostgreSQL not running")
            break
        else:
            print(f"   Error: {str(e)[:50]}")
    except Exception as e:
        print(f"   Error: {str(e)[:50]}")