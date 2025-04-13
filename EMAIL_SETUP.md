# Email Configuration Guide

This application uses SMTP2GO's SMTP relay server for all outbound email communications. This document provides instructions on how to set up and test the email functionality.

## SMTP2GO Configuration

The application is configured to use the following SMTP2GO settings:

- **SMTP Server**: mail.smtp2go.com
- **Primary Port**: 2525
- **Fallback Ports**: 8025, 587, 80
- **Security**: TLS
- **Authentication**: Required
- **Sender Email**: support@rvi.iam-alliance.com
- **Display Name**: IaMA RVI Support

## Required Environment Variables

To enable email functionality, you must set the following environment variable:

```
SMTP_RELAY_AUTHPW=your_smtp_password
```

This can be added to your `.env` file or set in your deployment environment.

## SMTP2GO Authentication

1. The sender email address (support@rvi.iam-alliance.com) is used as the username for SMTP authentication
2. The password is stored in the SMTP_RELAY_AUTHPW environment variable

## Testing Email Functionality

A test script has been provided to verify that your SMTP2GO configuration is working correctly. Run:

```bash
# Set environment variable first
export SMTP_RELAY_AUTHPW=your_password

# Then run the test script with a recipient email
python test_smtp.py recipient@example.com
```

This will send a test email to the specified recipient.

## Troubleshooting

If emails are not being sent:

1. **Check Credentials**: Ensure your SMTP password is correct and the SMTP_RELAY_AUTHPW environment variable is set
2. **Network Issues**: Make sure your server can reach the SMTP2GO server (mail.smtp2go.com) on at least one of the configured ports
3. **Logs**: Check the application logs for error messages related to email sending (look for port-specific errors)
4. **Rate Limits**: Be aware of SMTP2GO's sending rate limits for your account tier
5. **Sender Domain**: Ensure your sender domain (rvi.iam-alliance.com) is properly configured in SMTP2GO's dashboard
6. **Firewall Rules**: Ensure your firewall allows outbound connections on the required ports (2525, 8025, 587, 80)

## Email Templates

Currently, the application uses the following email templates:

1. **Account Creation Notification** - Sent to both admin and new user when an account is created
2. **Matrix Token Notification** - Sent to admin when a Matrix registration token is generated

To modify these templates, edit the corresponding functions in `utils.py`.

## Production Considerations

For production use, consider:

1. **Domain Verification**: Verify your sender domain (rvi.iam-alliance.com) with SMTP2GO to improve deliverability
2. **SPF and DKIM**: Configure SPF and DKIM records for your sending domain in your DNS settings
3. **Monitoring**: Set up monitoring for email delivery rates and bounces through SMTP2GO's dashboard
4. **SMTP Ports**: Ensure your firewall and network configuration allow outbound connections on the primary port (2525) or at least one of the fallback ports
5. **Email Templates**: Consider moving email templates to separate files for easier maintenance
6. **Error Handling**: Configure notifications for failed email deliveries to ensure critical communications aren't missed