import os
import sys
from werkzeug.security import generate_password_hash

# Add the current directory to path so we can import our modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app, db
from models import User

def reset_superadmin_password(new_password="Admin123!"):
    with app.app_context():
        # Find the superadmin user
        superadmin = User.query.filter_by(username='superadmin').first()
        
        if not superadmin:
            print("Error: Superadmin user not found")
            return False
        
        # Update the password
        superadmin.password_hash = generate_password_hash(new_password)
        
        # If the account was set to require password change, remove that requirement
        superadmin.needs_password_change = False
        
        # Save changes to the database
        db.session.commit()
        
        print(f"Superadmin password has been reset to: {new_password}")
        return True

if __name__ == "__main__":
    reset_superadmin_password()