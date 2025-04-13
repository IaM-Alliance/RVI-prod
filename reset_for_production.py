#!/usr/bin/env python3
"""
Reset Database for Production Deployment

This script performs the following operations:
1. Clears all existing data from the database
2. Sets up a fresh superadmin account
3. Removes any uploaded files

Usage:
    python reset_for_production.py
"""

import os
import sys
import shutil
from datetime import datetime
from werkzeug.security import generate_password_hash
from sqlalchemy import text
from app import app, db
from models import User, AuditLog, VettingForm, VettingEvidence, MatrixToken, UserPreferences


def reset_database():
    """Reset all database tables and create a fresh superadmin account"""
    with app.app_context():
        try:
            print("Starting database reset...")
            
            # Drop all existing data
            print("Removing all data from tables...")
            # Execute raw SQL to bypass foreign key constraints
            db.session.execute(text("SET CONSTRAINTS ALL DEFERRED"))
            UserPreferences.query.delete()
            MatrixToken.query.delete()
            VettingEvidence.query.delete()
            VettingForm.query.delete()
            AuditLog.query.delete()
            User.query.delete()
            db.session.commit()
            print("✓ All table data removed")
            
            # Create the superadmin account
            print("\nCreating superadmin account...")
            superadmin = User(
                username="Superadmin-SNC",
                email="admin@hq.iam-alliance.com",
                password_hash=generate_password_hash("thieZijee1yoh5UZee9Lahqu"),
                role="superadmin",
                created_at=datetime.utcnow(),
                status="active",
                needs_password_change=True
                # created_by and approved_by will be set after we have the ID
            )
            db.session.add(superadmin)
            db.session.flush()  # Get ID without committing
            
            # Now set the self-references
            superadmin.created_by = superadmin.id
            superadmin.approved_by = superadmin.id
            superadmin.approved_at = datetime.utcnow()
            
            db.session.commit()
            print(f"✓ Superadmin created with ID: {superadmin.id}")
            
            # Add initial audit log entry
            log_entry = AuditLog(
                user_id=superadmin.id,
                action="system_reset",
                details="System reset for production deployment",
                ip_address="system"
            )
            db.session.add(log_entry)
            db.session.commit()
            print("✓ Initial audit log created")
            
            # Create user preferences for superadmin
            preferences = UserPreferences(user_id=superadmin.id)
            db.session.add(preferences)
            db.session.commit()
            print("✓ User preferences created")
            
            print("\nDatabase reset completed successfully!")
            return True
            
        except Exception as e:
            db.session.rollback()
            print(f"Error: {str(e)}")
            return False


def clean_uploaded_files():
    """Remove all uploaded files"""
    try:
        # Clear the uploads/evidence directory
        upload_dir = app.config["UPLOAD_FOLDER"]
        if os.path.exists(upload_dir):
            # Remove all files but keep the directory
            for filename in os.listdir(upload_dir):
                file_path = os.path.join(upload_dir, filename)
                if os.path.isfile(file_path):
                    os.unlink(file_path)
                    print(f"Deleted file: {file_path}")
            print("✓ All uploaded files removed")
        else:
            print("Upload directory doesn't exist, creating it...")
            os.makedirs(upload_dir, mode=0o750, exist_ok=True)
            print("✓ Upload directory created with secure permissions")
            
        return True
    except Exception as e:
        print(f"Error cleaning uploaded files: {str(e)}")
        return False


if __name__ == "__main__":
    print("=== IAM Alliance Vetting System - Production Reset ===\n")
    
    # Confirm action
    confirm = input("This will delete ALL data and create a fresh superadmin account. Continue? (y/N): ")
    if confirm.lower() != 'y':
        print("Operation cancelled.")
        sys.exit(0)
    
    # Reset database
    print("\n1. Resetting database...")
    if reset_database():
        print("Database reset successful.")
    else:
        print("Database reset failed.")
        sys.exit(1)
    
    # Clean uploaded files
    print("\n2. Cleaning uploaded files...")
    if clean_uploaded_files():
        print("File cleanup successful.")
    else:
        print("File cleanup failed.")
        sys.exit(1)
    
    print("\n=== Production Reset Complete ===")
    print("""
The system has been reset with a single superadmin account:

Username: Superadmin-SNC
Email: admin@hq.iam-alliance.com
Password: thieZijee1yoh5UZee9Lahqu

The user will be prompted to change this password upon first login.
    """)