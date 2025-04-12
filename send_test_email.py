import os
from utils import send_email

# Send a test email
recipient = "faustin.zaiah@magneticoak.com"
subject = "test"
body = "test"

success = send_email(recipient, subject, body)
print(f"Email sending {'successful' if success else 'failed'}")