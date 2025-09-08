import os
import sqlite3
import psycopg2
from psycopg2.extras import RealDictCursor
import logging
from datetime import datetime
import json

class DatabaseMigrator:
    """Handle database migrations between SQLite and PostgreSQL"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.sqlite_db = os.path.join(os.path.dirname(__file__), 'criminals.db')
        
        # PostgreSQL connection parameters from environment
        self.pg_config = {
            'host': os.getenv('DB_HOST', 'localhost'),
            'port': os.getenv('DB_PORT', '5432'),
            'database': os.getenv('DB_NAME', 'biometric_crime_db'),
            'user': os.getenv('DB_USER', 'postgres'),
            'password': os.getenv('DB_PASSWORD', '')
        }
    
    def create_postgresql_tables(self):
        """Create PostgreSQL tables with enhanced schema"""
        try:
            conn = psycopg2.connect(**self.pg_config)
            cursor = conn.cursor()
            
            # Create criminals table with enhanced fields
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS criminals (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(255) NOT NULL,
                    crime TEXT,
                    face_image TEXT,
                    fingerprint_image TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status VARCHAR(50) DEFAULT 'active',
                    risk_level VARCHAR(20) DEFAULT 'medium',
                    additional_info JSONB,
                    face_encoding BYTEA,
                    fingerprint_features JSONB
                )
            """)
            
            # Create admin table with enhanced security
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS admin (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(100) NOT NULL UNIQUE,
                    password BYTEA NOT NULL,
                    role VARCHAR(50) DEFAULT 'admin',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    is_active BOOLEAN DEFAULT TRUE,
                    failed_login_attempts INTEGER DEFAULT 0,
                    locked_until TIMESTAMP,
                    email VARCHAR(255),
                    phone VARCHAR(20),
                    permissions JSONB
                )
            """)
            
            # Create audit log table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES admin(id),
                    action VARCHAR(100) NOT NULL,
                    table_name VARCHAR(50),
                    record_id INTEGER,
                    old_values JSONB,
                    new_values JSONB,
                    ip_address INET,
                    user_agent TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create sessions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS user_sessions (
                    id SERIAL PRIMARY KEY,
                    session_id VARCHAR(255) UNIQUE NOT NULL,
                    user_id INTEGER REFERENCES admin(id),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    ip_address INET,
                    user_agent TEXT,
                    is_active BOOLEAN DEFAULT TRUE
                )
            """)
            
            # Create detection_results table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS detection_results (
                    id SERIAL PRIMARY KEY,
                    detection_type VARCHAR(20) NOT NULL, -- 'face' or 'fingerprint'
                    criminal_id INTEGER REFERENCES criminals(id),
                    confidence_score DECIMAL(5,4),
                    detection_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    image_path TEXT,
                    location_data JSONB,
                    operator_id INTEGER REFERENCES admin(id),
                    verified BOOLEAN DEFAULT FALSE,
                    notes TEXT
                )
            """)
            
            # Create indexes for better performance
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_criminals_name ON criminals(name)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_criminals_status ON criminals(status)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_admin_username ON admin(username)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_detection_results_time ON detection_results(detection_time)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_sessions_expires ON user_sessions(expires_at)")
            
            conn.commit()
            cursor.close()
            conn.close()
            
            self.logger.info("PostgreSQL tables created successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error creating PostgreSQL tables: {e}")
            return False
    
    def migrate_data_to_postgresql(self):
        """Migrate data from SQLite to PostgreSQL"""
        try:
            # Connect to SQLite
            sqlite_conn = sqlite3.connect(self.sqlite_db)
            sqlite_conn.row_factory = sqlite3.Row
            sqlite_cursor = sqlite_conn.cursor()
            
            # Connect to PostgreSQL
            pg_conn = psycopg2.connect(**self.pg_config)
            pg_cursor = pg_conn.cursor()
            
            # Migrate criminals table
            sqlite_cursor.execute("SELECT * FROM criminals")
            criminals = sqlite_cursor.fetchall()
            
            for criminal in criminals:
                pg_cursor.execute("""
                    INSERT INTO criminals (id, name, crime, face_image, fingerprint_image, status, risk_level)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (id) DO UPDATE SET
                        name = EXCLUDED.name,
                        crime = EXCLUDED.crime,
                        face_image = EXCLUDED.face_image,
                        fingerprint_image = EXCLUDED.fingerprint_image,
                        updated_at = CURRENT_TIMESTAMP
                """, (
                    criminal['id'], criminal['name'], criminal['crime'],
                    criminal['face_image'], criminal['fingerprint_image'],
                    'active', 'medium'
                ))
            
            # Migrate admin table
            sqlite_cursor.execute("SELECT * FROM admin")
            admins = sqlite_cursor.fetchall()
            
            for admin in admins:
                pg_cursor.execute("""
                    INSERT INTO admin (id, username, password, role, is_active)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (username) DO UPDATE SET
                        password = EXCLUDED.password,
                        role = EXCLUDED.role
                """, (
                    admin['id'], admin['username'], admin['password'],
                    admin['role'], True
                ))
            
            pg_conn.commit()
            
            # Update sequences
            pg_cursor.execute("SELECT setval('criminals_id_seq', (SELECT MAX(id) FROM criminals))")
            pg_cursor.execute("SELECT setval('admin_id_seq', (SELECT MAX(id) FROM admin))")
            
            pg_conn.commit()
            pg_cursor.close()
            pg_conn.close()
            sqlite_cursor.close()
            sqlite_conn.close()
            
            self.logger.info("Data migration completed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error migrating data: {e}")
            return False
    
    def backup_sqlite_database(self, backup_path=None):
        """Create a backup of the SQLite database"""
        if backup_path is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_path = f"backup_criminals_{timestamp}.db"
        
        try:
            import shutil
            shutil.copy2(self.sqlite_db, backup_path)
            self.logger.info(f"Database backup created: {backup_path}")
            return backup_path
        except Exception as e:
            self.logger.error(f"Error creating backup: {e}")
            return None
    
    def test_postgresql_connection(self):
        """Test PostgreSQL connection"""
        try:
            conn = psycopg2.connect(**self.pg_config)
            cursor = conn.cursor()
            cursor.execute("SELECT version()")
            version = cursor.fetchone()
            cursor.close()
            conn.close()
            self.logger.info(f"PostgreSQL connection successful: {version[0]}")
            return True
        except Exception as e:
            self.logger.error(f"PostgreSQL connection failed: {e}")
            return False
    
    def run_full_migration(self):
        """Run complete migration process"""
        self.logger.info("Starting database migration process")
        
        # Step 1: Test PostgreSQL connection
        if not self.test_postgresql_connection():
            self.logger.error("Cannot connect to PostgreSQL. Migration aborted.")
            return False
        
        # Step 2: Create backup
        backup_path = self.backup_sqlite_database()
        if not backup_path:
            self.logger.error("Backup creation failed. Migration aborted.")
            return False
        
        # Step 3: Create PostgreSQL tables
        if not self.create_postgresql_tables():
            self.logger.error("Table creation failed. Migration aborted.")
            return False
        
        # Step 4: Migrate data
        if not self.migrate_data_to_postgresql():
            self.logger.error("Data migration failed.")
            return False
        
        self.logger.info("Database migration completed successfully")
        return True

def create_database_config():
    """Create database configuration utility"""
    
    class DatabaseConfig:
        def __init__(self):
            self.use_postgresql = os.getenv('USE_POSTGRESQL', 'False').lower() == 'true'
            
        def get_connection(self):
            """Get appropriate database connection"""
            if self.use_postgresql:
                return psycopg2.connect(
                    host=os.getenv('DB_HOST', 'localhost'),
                    port=os.getenv('DB_PORT', '5432'),
                    database=os.getenv('DB_NAME', 'biometric_crime_db'),
                    user=os.getenv('DB_USER', 'postgres'),
                    password=os.getenv('DB_PASSWORD', '')
                )
            else:
                db_path = os.path.join(os.path.dirname(__file__), 'criminals.db')
                return sqlite3.connect(db_path)
        
        def execute_query(self, query, params=None):
            """Execute query with appropriate database"""
            conn = self.get_connection()
            cursor = conn.cursor()
            
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            
            if query.strip().upper().startswith('SELECT'):
                result = cursor.fetchall()
            else:
                conn.commit()
                result = cursor.rowcount
            
            cursor.close()
            conn.close()
            return result
    
    return DatabaseConfig()

if __name__ == '__main__':
    # Example usage
    migrator = DatabaseMigrator()
    migrator.run_full_migration()