import sqlite3
import os

DATABASE = "cyber_guardian.db"

def fix_database():
    print("🔧 Fixing database...")
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    try:
        # Check if 'plan' column exists
        cursor.execute("PRAGMA table_info(users)")
        columns = cursor.fetchall()
        
        column_names = [col[1] for col in columns]
        
        if 'plan' not in column_names:
            print("✅ Adding 'plan' column...")
            cursor.execute("ALTER TABLE users ADD COLUMN plan TEXT DEFAULT 'free'")
            conn.commit()
            print("✅ Column added successfully!")
        else:
            print("✅ 'plan' column already exists!")
        
        # Set default plan for existing users
        cursor.execute("UPDATE users SET plan = 'free' WHERE plan IS NULL")
        conn.commit()
        print("✅ Default 'free' plan set for all users!")
        
        # Verify
        cursor.execute("SELECT username, plan FROM users")
        users = cursor.fetchall()
        print("\n📋 Current Users:")
        for user in users:
            print(f"   - {user[0]}: {user[1]}")
            
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        conn.close()
        print("\n✅ Done! You can now restart your app.")

if __name__ == "__main__":
    fix_database()