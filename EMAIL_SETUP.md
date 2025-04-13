# Email Configuration Guide

This application uses Mailjet's SMTP server for all outbound email communications. This document provides instructions on how to set up and test the email functionality.

## Mailjet SMTP Configuration

The application is configured to use the following Mailjet SMTP settings:

- **SMTP Server**: in-v3.mailjet.com
- **Port**: 587
- **Security**: TLS
- **Authentication**: Required

## Required Environment Variables

To enable email functionality, you must set the following environment variables:

```
MAILJET_API_KEY=your_mailjet_api_key
MAILJET_SECRET_KEY=your_mailjet_secret_key
```

These can be added to your `.env` file or set in your deployment environment.

## Getting Mailjet Credentials

1. Sign up for a Mailjet account at [https://www.mailjet.com/](https://www.mailjet.com/)
2. Navigate to Account Settings → API Key Management
3. Create a new API key pair or use the existing one
4. The API Key is used as the SMTP username, and the Secret Key is used as the SMTP password

## Testing Email Functionality

A test script has been provided to verify that your Mailjet configuration is working correctly. Run:

```bash
# Set environment variables first
export MAILJET_API_KEY=your_key
export MAILJET_SECRET_KEY=your_secret

# Then run the test script with a recipient email
python test_mailjet_smtp.py recipient@example.com
```

This will send a test email to the specified recipient.

## Troubleshooting

If emails are not being sent:

1. **Check Credentials**: Ensure your Mailjet API Key and Secret Key are correct
2. **Network Issues**: Make sure your server can reach Mailjet's SMTP server (in-v3.mailjet.com) on port 587
3. **Logs**: Check the application logs for error messages related to email sending
4. **Rate Limits**: Be aware of Mailjet's sending rate limits for your account tier
5. **Sender Domain**: Ensure your sender domain (support@app.iam-alliance.com) is properly configured in Mailjet

## Email Templates

Currently, the application uses the following email templates:

1. **Account Creation Notification** - Sent to both admin and new user when an account is created
2. **Matrix Token Notification** - Sent to admin when a Matrix registration token is generated

To modify these templates, edit the corresponding functions in `utils.py`.

## Production Considerations

For production use, consider:

1. **Domain Verification**: Verify your sender domain with Mailjet to improve deliverability
2. **SPF and DKIM**: Configure SPF and DKIM records for your sending domain
3. **Monitoring**: Set up monitoring for email delivery rates and bounces
4. **Fallback Service**: Consider implementing a fallback email service for critical emails