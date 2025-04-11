import os
import sys
from app import app, db
from models import User, AuditLog, MatrixToken, VettingForm
from sqlalchemy import text
from werkzeug.security import generate_password_hash
from datetime import datetime

def migrate_database():
    print("Starting database migration...")
    
    with app.app_context():
        try:
            # Check if 'status' column exists in the User table
            check_query = text("SELECT column_name FROM information_schema.columns WHERE table_name='user' AND column_name='status'")
            result = db.session.execute(check_query).fetchone()
            
            # If column doesn't exist, add the necessary columns
            if not result:
                print("Adding new columns to User table...")
                
                # Add status column
                db.session.execute(text("ALTER TABLE \"user\" ADD COLUMN status VARCHAR(20) NOT NULL DEFAULT 'active'"))
                
                # Add approved_by column
                db.session.execute(text("ALTER TABLE \"user\" ADD COLUMN approved_by INTEGER REFERENCES \"user\"(id)"))
                
                # Add approved_at column
                db.session.execute(text("ALTER TABLE \"user\" ADD COLUMN approved_at TIMESTAMP"))
                
                # Add approval_notes column
                db.session.execute(text("ALTER TABLE \"user\" ADD COLUMN approval_notes TEXT"))
                
                # Set all existing users as approved by superadmin (id=1)
                db.session.execute(text("UPDATE \"user\" SET approved_by=1, approved_at=created_at"))
                
                db.session.commit()
                print("Migration completed successfully!")
            else:
                print("Migration already applied. Skipping...")
        
        except Exception as e:
            print(f"Migration failed: {str(e)}")
            db.session.rollback()
            sys.exit(1)
        
        # Create or update superadmin user
        superadmin = User.query.filter_by(username='superadmin').first()
        if not superadmin:
            print("Creating superadmin user...")
            superadmin = User(
                username='superadmin',
                email='admin@iam-alliance.com',
                password_hash=generate_password_hash("Admin123!"),
                role='superadmin',
                needs_password_change=False,
                status='active',
                approved_at=datetime.utcnow()
            )
            db.session.add(superadmin)
            db.session.commit()
            print("Superadmin created with password: Admin123!")
        else:
            print("Superadmin user already exists.")
            
        print("Database is now up to date!")

if __name__ == "__main__":
    migrate_database()