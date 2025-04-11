from app import app, db
from models import User
from werkzeug.security import generate_password_hash

with app.app_context():
    # Find the superadmin user
    user = User.query.filter_by(username='superadmin').first()
    
    if user:
        print(f'Superadmin exists with email: {user.email}')
        # Reset password
        new_password = 'Admin123!'
        user.password_hash = generate_password_hash(new_password)
        user.needs_password_change = True
        db.session.commit()
        print(f'Password reset to: {new_password}')
    else:
        # Create superadmin if it doesn't exist
        new_password = 'Admin123!'
        superadmin = User(
            username='superadmin',
            email='admin@iam-alliance.com',
            password_hash=generate_password_hash(new_password),
            role='superadmin',
            needs_password_change=True
        )
        db.session.add(superadmin)
        db.session.commit()
        print(f'Created new superadmin with password: {new_password}')