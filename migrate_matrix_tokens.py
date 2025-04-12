import os
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
import sys
from datetime import datetime

def migrate_matrix_tokens():
    print("Starting MatrixToken table migration...")
    
    # Connect to the database
    DATABASE_URL = os.environ.get("DATABASE_URL")
    if not DATABASE_URL:
        raise ValueError("DATABASE_URL environment variable not set")
    
    conn = None
    cursor = None
    
    try:
        conn = psycopg2.connect(DATABASE_URL)
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cursor = conn.cursor()
        
        # Check if 'assigned_username' column exists in the matrix_token table
        cursor.execute("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name='matrix_token' AND column_name='assigned_username'
        """)
        result = cursor.fetchone()
        
        if not result:
            print("Adding new columns to MatrixToken table...")
            
            try:
                # Add assigned_username column with default value
                cursor.execute("""
                    ALTER TABLE "matrix_token" 
                    ADD COLUMN assigned_username VARCHAR(120) DEFAULT 'legacy_user'
                """)
                
                # Set all existing tokens to no longer be nullable
                cursor.execute("""
                    ALTER TABLE "matrix_token" 
                    ALTER COLUMN assigned_username SET NOT NULL
                """)
                
                # Add response_timestamp column
                cursor.execute("""
                    ALTER TABLE "matrix_token" 
                    ADD COLUMN response_timestamp TIMESTAMP
                """)
                
                # Add expiry_time column (for Unix timestamp)
                cursor.execute("""
                    ALTER TABLE "matrix_token" 
                    ADD COLUMN expiry_time BIGINT
                """)
                
                # Add expiry_date column (for formatted date)
                cursor.execute("""
                    ALTER TABLE "matrix_token" 
                    ADD COLUMN expiry_date VARCHAR(20)
                """)
                
                # Add uses_allowed column with default value of 1
                cursor.execute("""
                    ALTER TABLE "matrix_token" 
                    ADD COLUMN uses_allowed INTEGER DEFAULT 1
                """)
                
                print("MatrixToken table migration completed successfully!")
            except Exception as e:
                print(f"Error altering table: {str(e)}")
                conn.rollback()
                raise
        else:
            print("MatrixToken migration already applied. Skipping...")
            
    except Exception as e:
        print(f"Migration failed: {str(e)}")
        if conn:
            conn.rollback()
        sys.exit(1)
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

if __name__ == "__main__":
    migrate_matrix_tokens()