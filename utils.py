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
    """Send an email using SMTP2GO relay server."""
    try:
        # SMTP2GO configuration
        smtp_host = "mail.smtp2go.com"  # Primary SMTP server
        primary_port = 2525  # Preferred TLS port
        fallback_ports = [8025, 587, 80]  # Fallback TLS ports
        sender_email = "support@rvi.iam-alliance.com"  # Default sender email
        smtp_username = os.environ.get("SMTP_RELAY_USER", sender_email)  # Use env var or default to sender_email
        smtp_password = os.environ.get("SMTP_RELAY_AUTHPW")
        
        if not smtp_password:
            logger.error("SMTP relay password not configured. Email cannot be sent.")
            return False
        
        # Create message
        msg = MIMEMultipart()
        msg['From'] = f"IaMA RVI Support <{sender_email}>"
        msg['To'] = to_email
        msg['Subject'] = subject
        
        # Attach body
        msg.attach(MIMEText(body, 'plain'))
        
        # Try primary port first, then fallbacks if needed
        ports_to_try = [primary_port] + fallback_ports
        
        for port in ports_to_try:
            try:
                logger.info(f"Connecting to SMTP server {smtp_host} on port {port}")
                with smtplib.SMTP(smtp_host, port) as server:
                    server.ehlo()
                    server.starttls()
                    server.ehlo()
                    
                    # Authenticate with SMTP2GO
                    logger.info(f"Authenticating with SMTP2GO using username: {smtp_username}")
                    server.login(smtp_username, smtp_password)
                    
                    # Send the email
                    server.send_message(msg)
                    logger.info(f"Email sent successfully to {to_email} via port {port}")
                
                # If we reach here, email was sent successfully
                return True
                
            except Exception as port_error:
                logger.warning(f"Failed to send email via port {port}: {str(port_error)}")
                # Continue to next port if this one failed
                continue
        
        # If we get here, all ports failed
        logger.error("All SMTP ports failed. Email could not be sent.")
        return False
        
    except Exception as e:
        logger.error(f"Failed to send email: {str(e)}")
        return False

def send_account_notification(admin_email, user_email, username, admin_name):
    """Send notification emails to both admin and new user."""
    # Send to admin
    admin_subject = f"New RVI User Account Created: {username}"
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
    user_subject = "Welcome to IaM-Alliance Registration Vetting and Invitation System"
    user_body = f"""
    Hello {username},
    
    An account has been created for you on the IaM-Alliance Vetting System.  The URL for the site is:
    https://rvi.iam-alliance.com 
    
    Your username is: {username}
    
    A server administrator will send you the temporary password separately via Signal or Element chat message.
    
    Upon first login, you will be prompted to change your password.
    
    If you need password assistance, please contact a server administrator via Signal, Element, or email support@rvi.iam-alliance.com.
    
    Regards,
    IaM-Alliance Registration Vetting and Invitation System
    """
    
    send_email(user_email, user_subject, user_body)
    
    
def send_token_notification(admin_email, admin_name, full_name, email, assigned_username, token, expiry_date, vetting_info):
    """Send notification email to admin with token and vetting information."""
    subject = f"Matrix Registration Token for {full_name}"
    
    verification_info = f"Verification method: {vetting_info.get('verification_method', 'Not specified')}\n"
    if vetting_info.get('verification_date'):
        verification_info += f"Verification date: {vetting_info.get('verification_date')}\n"
    verification_info += f"Verification location: {vetting_info.get('verification_location', 'Not specified')}"
    
    vetting_info_text = f"""
Vetting Score: {vetting_info.get('vetting_score', 'Not specified')}
Vetting Notes: {vetting_info.get('vetting_notes', 'None')}
"""
    
    body = f"""
Hello {admin_name},

A Matrix registration token has been generated for an approved applicant:

APPLICANT INFORMATION:
Full Name: {full_name}
Email: {email}
Assigned Username: {assigned_username}

VETTING DETAILS:
{verification_info}
{vetting_info_text}

TOKEN INFORMATION:
Token: {token}
Expiry Date: {expiry_date}

NEXT STEPS:
This token is ready for the approved new member to use. 

1. First, please send the person a Signal message - or an email if the person is not available on Signal - informing them that they are approved as a new member of IaM-Alliance. 

2. In that message, include the Assigned Username (with the caveat that if they do not use the assigned username, their account may be deleted and replaced). 

3. The message should also include a link to the FAQs and User Guide for the Element chat client application, and a link to element.iam-alliance.com.

4. IN A SEPARATE NEW MESSAGE: Please provide the token to the person via a Signal message - or an email if the person is not available on Signal. In the second message, include only the token and expiration date of the token.

Regards,
IaM-Alliance System
"""
    
    return send_email(admin_email, subject, body)

import requests
import time
import json
from datetime import datetime, timedelta

def matrix_api_post(user_fullname, user_email, assigned_username):
    """
    Request the Matrix API to generate a new registration token.
    Instead of creating our own token, we ask the Matrix server to create one.
    """
    try:
        # Endpoint to create a new token (without specifying token value)
        api_url = "https://matrix.iam-alliance.com/_synapse/admin/v1/registration_tokens/new"
        bearer_token = os.environ.get('MATRIX_ADMIN_TOKEN')
        
        if not bearer_token:
            logger.error("MATRIX_ADMIN_TOKEN environment variable not set")
            return {
                "success": False,
                "error": "API Bearer Token not configured",
                "response": None
            }
        
        # Calculate expiry time (30 days from now in milliseconds since epoch)
        expiry_time_seconds = int(time.time()) + (30 * 24 * 60 * 60)  # 30 days in seconds
        expiry_time_ms = expiry_time_seconds * 1000  # Convert to milliseconds
        
        # Prepare request data based on the documented token object structure
        request_data = {
            "uses_allowed": 1,
            "expiry_time": expiry_time_ms
        }
        
        # Make the API request - using POST to create a new token
        response = requests.post(
            api_url,
            json=request_data,
            headers={
                "Authorization": f"Bearer {bearer_token}",
                "Accept": "application/json",
                "Content-Type": "application/json"
            },
            timeout=10
        )
        
        # Parse the response
        if response.status_code == 200:
            response_data = response.json()
            
            # Calculate the expiry date in the format YYYY-MMM-DD
            # Subtract 48 hours (172800 seconds) from the expiry time as specified
            adjusted_expiry_time = expiry_time_seconds - 172800
            expiry_date = datetime.fromtimestamp(adjusted_expiry_time).strftime('%Y-%b-%d')
            
            # Return success response with parsed data
            return {
                "success": True,
                "response": response_data,
                "expiry_time": expiry_time_ms,
                "expiry_date": expiry_date,
                "response_timestamp": datetime.utcnow().isoformat() + 'Z'  # ISO 8601 format with Z for UTC
            }
        else:
            # Log error details
            logger.error(f"Matrix API error: {response.status_code}, Response: {response.text}")
            
            # Return error response
            return {
                "success": False,
                "error": f"API returned status code {response.status_code}",
                "response": response.text
            }
    except Exception as e:
        # Log exception
        logger.error(f"Exception in matrix_api_post: {str(e)}", exc_info=True)
        
        # Return exception details
        return {
            "success": False,
            "error": str(e),
            "response": None
        }
    
    
def get_matrix_token_info(token):
    """
    Get information about a specific Matrix token from the Matrix API.
    Returns status of token including usage (pending/completed) based on Matrix API documentation.
    """
    try:
        # Matching the same API endpoint structure shown in the documentation
        api_url = f"https://matrix.iam-alliance.com/_synapse/admin/v1/registration_tokens/{token}"
        bearer_token = os.environ.get('MATRIX_ADMIN_TOKEN')
        
        if not bearer_token:
            logger.error("MATRIX_ADMIN_TOKEN environment variable not set")
            return {
                "success": False,
                "error": "API Bearer Token not configured",
                "response": None
            }
        
        # Make the API request with the appropriate headers
        response = requests.get(
            api_url,
            headers={
                "Authorization": f"Bearer {bearer_token}",
                "Accept": "application/json"
            },
            timeout=10
        )
        
        # Parse the response
        if response.status_code == 200:
            response_data = response.json()
            
            # API returns token details with usage status: pending, completed, uses_allowed, expiry_time
            return {
                "success": True,
                "response": response_data,
                "timestamp": datetime.utcnow().isoformat() + 'Z'  # ISO 8601 format
            }
        else:
            # Log error details
            logger.error(f"Matrix API error: {response.status_code}, Response: {response.text}")
            
            # Return error response
            return {
                "success": False,
                "error": f"API returned status code {response.status_code}",
                "response": response.text
            }
    except Exception as e:
        # Log exception
        logger.error(f"Exception in get_matrix_token_info: {str(e)}", exc_info=True)
        
        # Return exception details
        return {
            "success": False,
            "error": str(e),
            "response": None
        }
