import os
import random
import string
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logger = logging.getLogger(__name__)

def generate_random_password(length=12):
    """Generate a random secure password."""
    characters = string.ascii_letters + string.digits + string.punctuation
    # Ensure at least one of each type of character
    password = [
        random.choice(string.ascii_lowercase),
        random.choice(string.ascii_uppercase),
        random.choice(string.digits),
        random.choice('!@#$%^&*()_-+=')
    ]
    # Fill the rest of the password with random characters
    password.extend(random.choice(characters) for _ in range(length - len(password)))
    # Shuffle the password characters
    random.shuffle(password)
    return ''.join(password)

def send_email(to_email, subject, body):
    """Send an email using Postfix."""
    try:
        # Configure SMTP details
        smtp_host = "localhost"  # Assuming Postfix is running locally
        
        # Create message
        msg = MIMEMultipart()
        msg['From'] = "noreply@iam-alliance.com"
        msg['To'] = to_email
        msg['Subject'] = subject
        
        # Attach body
        msg.attach(MIMEText(body, 'plain'))
        
        # Send email
        with smtplib.SMTP(smtp_host) as server:
            server.send_message(msg)
        
        return True
    except Exception as e:
        logger.error(f"Failed to send email: {str(e)}")
        return False

def send_account_notification(admin_email, user_email, username, admin_name):
    """Send notification emails to both admin and new user."""
    # Send to admin
    admin_subject = f"New User Account Created: {username}"
    admin_body = f"""
    Hello {admin_name},
    
    A new user account has been created:
    
    Username: {username}
    Email: {user_email}
    
    A temporary password has been generated for this account. Please provide it to the user via Signal or Element chat message.
    
    Regards,
    IaM-Alliance System
    """
    
    send_email(admin_email, admin_subject, admin_body)
    
    # Send to user
    user_subject = "Welcome to IaM-Alliance Vetting System"
    user_body = f"""
    Hello {username},
    
    An account has been created for you on the IaM-Alliance Vetting System.
    
    Your username is: {username}
    
    A server administrator will send you the temporary password separately via Signal or Element chat message.
    
    Upon first login, you will be prompted to change your password.
    
    If you need password assistance, please contact a server administrator via Signal, Element, or email support@iam-alliance.com.
    
    Regards,
    IaM-Alliance System
    """
    
    send_email(user_email, user_subject, user_body)

def matrix_api_post(token, user_fullname, user_email):
    """
    Post a registration token to the Matrix API.
    In a production environment, this would be implemented to make the actual API call.
    """
    # This is a placeholder for the actual API implementation
    # In a real implementation, we would import requests and make a POST request
    
    api_url = "https://matrix.iam-alliance.com"
    
    # The actual API implementation would look something like this:
    """
    try:
        response = requests.post(
            api_url,
            json={
                "token": token,
                "fullname": user_fullname,
                "email": user_email
            },
            headers={
                "Authorization": f"Bearer {os.environ.get('MATRIX_API_KEY')}"
            },
            timeout=10
        )
        
        if response.status_code == 200:
            return {
                "success": True,
                "response": response.json()
            }
        else:
            return {
                "success": False,
                "error": f"API returned status code {response.status_code}",
                "response": response.text
            }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }
    """
    
    # For now, just return a successful response
    return {
        "success": True,
        "response": {
            "status": "registered",
            "message": "User registration submitted successfully"
        }
    }
