import sqlite3, os
def create_db():
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'criminals.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS criminals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            crime TEXT,
            face_image TEXT,
            fingerprint_image TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS admin (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password BLOB NOT NULL,
            role TEXT DEFAULT 'admin'
        )
    ''')

    # Clear existing admin accounts and insert new ones
    import bcrypt
    try:
        # Clear all existing admin accounts
        cursor.execute("DELETE FROM admin")
        print("[INFO] Cleared all existing admin accounts")
        
        # Insert shawad18 as admin
        admin_pw = bcrypt.hashpw(b"Sunee@18", bcrypt.gensalt())
        cursor.execute("INSERT INTO admin (username, password, role) VALUES (?, ?, ?)", ("shawad18", admin_pw, "admin"))
        print("[INFO] Created admin account: shawad18")
        
        # Insert shamsu as superadmin
        super_pw = bcrypt.hashpw(b"Sunainah@18", bcrypt.gensalt())
        cursor.execute("INSERT INTO admin (username, password, role) VALUES (?, ?, ?)", ("shamsu", super_pw, "superadmin"))
        print("[INFO] Created superadmin account: shamsu")
        
    except Exception as e:
        print(f"[ERROR] Failed to create admin accounts: {e}")
        pass

    conn.commit()
    conn.close()
    print("[INFO] Database created at", db_path)

if __name__ == '__main__':
    create_db()
