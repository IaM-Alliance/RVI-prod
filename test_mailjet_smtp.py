#!/usr/bin/env python3
"""
Test script for Mailjet SMTP email configuration.

Usage:
  python test_mailjet_smtp.py recipient@example.com

Environment variables required:
  MAILJET_API_KEY
  MAILJET_SECRET_KEY
"""

import os
import sys
from utils import send_email

if __name__ == "__main__":
    # Check if we have a recipient
    if len(sys.argv) < 2:
        print("Usage: python test_mailjet_smtp.py recipient@example.com")
        sys.exit(1)
    
    recipient = sys.argv[1]
    
    # Check environment variables
    mailjet_api_key = os.environ.get("MAILJET_API_KEY")
    mailjet_secret_key = os.environ.get("MAILJET_SECRET_KEY")
    
    if not mailjet_api_key or not mailjet_secret_key:
        print("Error: Mailjet credentials not found in environment variables.")
        print("Please set MAILJET_API_KEY and MAILJET_SECRET_KEY.")
        sys.exit(1)
    
    print(f"Sending test email to {recipient}...")
    
    # Send a test email
    success = send_email(
        recipient,
        "Test Email from IaM-Alliance Vetting System",
        """
This is a test email to verify that the Mailjet SMTP integration is working correctly.

The system is configured to use:
- SMTP server: in-v3.mailjet.com
- Port: 587
- TLS: Enabled

If you're receiving this email, the configuration is working correctly.

Regards,
IaM-Alliance System
"""
    )
    
    if success:
        print("Email sent successfully!")
    else:
        print("Failed to send email. Check the logs for more details.")