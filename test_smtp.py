#!/usr/bin/env python3
"""
Test script for SMTP2GO email configuration.

Usage:
  python test_smtp.py recipient@example.com

Environment variables required:
  SMTP_RELAY_AUTHPW
"""

import os
import sys
from utils import send_email

if __name__ == "__main__":
    # Check if we have a recipient
    if len(sys.argv) < 2:
        print("Usage: python test_smtp.py recipient@example.com")
        sys.exit(1)
    
    recipient = sys.argv[1]
    
    # Check environment variables
    smtp_password = os.environ.get("SMTP_RELAY_AUTHPW")
    
    if not smtp_password:
        print("Error: SMTP password not found in environment variables.")
        print("Please set SMTP_RELAY_AUTHPW.")
        sys.exit(1)
    
    print(f"Sending test email to {recipient}...")
    
    # Send a test email
    success = send_email(
        recipient,
        "Test Email from IaM-Alliance Vetting System",
        """
This is a test email to verify that the SMTP2GO integration is working correctly.

The system is configured to use:
- SMTP server: mail.smtp2go.com
- Primary port: 2525 (with fallbacks: 8025, 587, 80)
- TLS: Enabled
- Sender: support@rvi.iam-alliance.com

If you're receiving this email, the configuration is working correctly.

Regards,
IaM-Alliance System
"""
    )
    
    if success:
        print("Email sent successfully!")
    else:
        print("Failed to send email. Check the logs for more details.")