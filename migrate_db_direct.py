import os
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
from werkzeug.security import generate_password_hash
from datetime import datetime

def migrate_database():
    print("Starting database migration...")
    
    # Connect to the database
    DATABASE_URL = os.environ.get("DATABASE_URL")
    if not DATABASE_URL:
        raise ValueError("DATABASE_URL environment variable not set")
    
    try:
        conn = psycopg2.connect(DATABASE_URL)
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cursor = conn.cursor()
        
        # Check if 'status' column exists in the User table
        cursor.execute("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name='user' AND column_name='status'
        """)
        result = cursor.fetchone()
        
        # If column doesn't exist, add the necessary columns
        if not result:
            print("Adding new columns to User table...")
            
            # Add status column
            cursor.execute("""
                ALTER TABLE "user" 
                ADD COLUMN status VARCHAR(20) NOT NULL DEFAULT 'active'
            """)
            
            # Add approved_by column
            cursor.execute("""
                ALTER TABLE "user" 
                ADD COLUMN approved_by INTEGER REFERENCES "user"(id)
            """)
            
            # Add approved_at column
            cursor.execute("""
                ALTER TABLE "user" 
                ADD COLUMN approved_at TIMESTAMP
            """)
            
            # Add approval_notes column
            cursor.execute("""
                ALTER TABLE "user" 
                ADD COLUMN approval_notes TEXT
            """)
            
            # Set all existing users as approved by superadmin (id=1)
            cursor.execute("""
                UPDATE "user" 
                SET approved_by=1, approved_at=created_at
            """)
            
            print("Migration completed successfully!")
        else:
            print("Migration already applied. Skipping...")
        
        # Check if superadmin exists
        cursor.execute("""
            SELECT id FROM "user" WHERE username = 'superadmin'
        """)
        superadmin = cursor.fetchone()
        
        if not superadmin:
            print("Creating superadmin user...")
            now = datetime.utcnow()
            cursor.execute("""
                INSERT INTO "user" (
                    username, email, password_hash, role, 
                    created_at, needs_password_change, status, approved_at
                ) VALUES (
                    'superadmin', 'admin@iam-alliance.com', %s, 'superadmin', 
                    %s, FALSE, 'active', %s
                )
            """, (
                generate_password_hash("Admin123!"),
                now,
                now
            ))
            print("Superadmin created with password: Admin123!")
        else:
            print("Superadmin user already exists.")
        
        # Create test vetting agent account
        cursor.execute("""
            SELECT id FROM "user" WHERE username = 'vetting-test'
        """)
        vetting_test = cursor.fetchone()
        
        if not vetting_test:
            print("Creating vetting-test user...")
            now = datetime.utcnow()
            cursor.execute("""
                INSERT INTO "user" (
                    username, email, password_hash, role, 
                    created_at, needs_password_change, created_by, status, approved_at
                ) VALUES (
                    'vetting-test', 'vetting-test@example.com', %s, 'vetting_agent', 
                    %s, FALSE, 1, 'active', %s
                )
            """, (
                generate_password_hash("Vetting123!"),
                now,
                now
            ))
            print("Vetting agent test account created.")
        
        # Create test inviting admin account
        cursor.execute("""
            SELECT id FROM "user" WHERE username = 'inviting-test'
        """)
        inviting_test = cursor.fetchone()
        
        if not inviting_test:
            print("Creating inviting-test user...")
            now = datetime.utcnow()
            cursor.execute("""
                INSERT INTO "user" (
                    username, email, password_hash, role, 
                    created_at, needs_password_change, created_by, status, approved_at
                ) VALUES (
                    'inviting-test', 'inviting-test@example.com', %s, 'inviting_admin', 
                    %s, FALSE, 1, 'active', %s
                )
            """, (
                generate_password_hash("Inviting123!"),
                now,
                now
            ))
            print("Inviting admin test account created.")
            
        print("Database is now up to date!")
        
    except Exception as e:
        print(f"Migration failed: {str(e)}")
        if conn:
            conn.rollback()
        raise
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

if __name__ == "__main__":
    migrate_database()