# Production Deployment Guide

This document outlines the security enhancements and configuration changes that have been made to prepare the application for a production environment, as well as additional steps that should be taken during deployment.

## Summary of Security Improvements

The following improvements have been made to make the application production-ready:

1. **Email Configuration**
   - Configured to use SMTP2GO relay server (mail.smtp2go.com) with multiple fallback ports (2525, 8025, 587, 80) and TLS
   - Set sender email to support@rvi.iam-alliance.com with display name "IaMA RVI Support"
   - Improved error handling for email sending failures
   - Added comprehensive logging for email operations

2. **Content Security Policy (CSP)**
   - Implemented stricter CSP settings for production
   - Removed unsafe-inline for better script security
   - Added robust CSP violation reporting endpoint with support for multiple content types
   - Made CSP reporting domain-aware (only activated in production)

3. **Rate Limiting**
   - Enhanced rate limiting configuration with more sophisticated strategy
   - Added support for distributed rate limiting in production
   - Configured with tiered limits (per minute, hour, and day)
   - Improved fallbacks for rate limiter failures

4. **File Upload Security**
   - Created automatic directory creation with secure permissions (750)
   - Added thorough file type validation
   - Implemented secure file naming with UUID generation

5. **Logging**
   - Improved logging format with structured data
   - Configured production-appropriate log levels
   - Added detailed error logging throughout the application

## Security Enhancements Implemented

1. **Logging Configuration**
   - Reduced verbosity for production (INFO level instead of DEBUG)
   - Structured log format with timestamps
   - Environment-aware log levels (DEBUG in development, INFO in production)

2. **Debug Mode**
   - Explicitly disabled debug mode for production
   - Created a fallback mechanism for enabling debug mode via environment variables

3. **Database Connection Settings**
   - Enhanced connection pool settings for production scale
   - Added more robust timeouts and connection management
   - Improved error handling for database connections

4. **Content Security Policy**
   - Implemented environment-aware CSP settings: permissive in development, stricter in production
   - Added reporting endpoint for CSP violations
   - Created balanced policy that maintains security while ensuring compatibility with required CDNs
   - Added domain-aware CSP configuration and violation monitoring

5. **Rate Limiting**
   - Improved rate limiting configuration for production traffic
   - Added support for distributed rate limiting in production
   - Enhanced rate limiting headers and error handling
   - More sophisticated rate limiting strategy

6. **File Upload Security**
   - Ensured upload directory exists with proper permissions
   - Added thorough validation for uploaded content

## Additional Deployment Steps Required

1. **Environment Variables**
   - Create a secure `.env` file with the following variables:
     ```
     # Security
     SESSION_SECRET=<secure_random_value>
     
     # Database
     DATABASE_URL=postgresql://<user>:<password>@<host>/<dbname>
     
     # Optional Matrix API integration
     MATRIX_ADMIN_TOKEN=<your_matrix_token>
     
     # Email configuration (SMTP2GO relay)
     SMTP_RELAY_AUTHPW=<your_smtp_password>
     ```
   - Set permissions on the `.env` file to be restricted: `chmod 600 .env`

2. **Web Server Configuration**
   - Configure a proper web server like Nginx as a reverse proxy
   - SSL/TLS setup with valid certificates (Let's Encrypt recommended)
   - Proper MIME type configuration
   - Compression and caching settings
   - Deny access to sensitive locations

3. **Database Security**
   - Set up daily database backups
   - Configure database with minimal permissions for the application user
   - Enable TLS encryption for database connections
   - Set strong passwords for database accounts

4. **File System Security**
   - Ensure proper permissions on uploaded files (750 for directories, 640 for files)
   - Regular backups of uploaded content
   - Consider using S3 or similar service for file storage in high-scale environments

5. **SSL/TLS Configuration**
   - Enable HTTPS with modern protocols (TLS 1.2+)
   - Strong cipher configuration
   - HSTS headers set properly
   - Consider OCSP stapling and certificate transparency

6. **Monitoring and Alerts**
   - Set up monitoring for the application
   - Configure alerts for downtime or errors
   - Implement centralized logging
   - Monitor for suspicious activity

7. **Regular Updates**
   - Set up a process for regular security updates
   - Plan for regular database maintenance
   - Monitor for outdated dependencies

## Recommended Nginx Configuration

```nginx
server {
    listen 80;
    server_name your-domain.com;
    
    # Redirect all traffic to HTTPS
    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl;
    server_name your-domain.com;
    
    # SSL Configuration
    ssl_certificate /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;
    
    # HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # Application location
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Static files
    location /static/ {
        alias /path/to/app/static/;
        expires 30d;
    }
    
    # Evidence files (served through Flask)
    location /uploads/ {
        internal; # Prevents direct access, files must be served through Flask
    }
    
    # Additional security headers
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
    
    # Logging
    access_log /var/log/nginx/app-access.log;
    error_log /var/log/nginx/app-error.log;
}
```

## Systemd Service Configuration

Create a systemd service file to manage the application process:

```ini
[Unit]
Description=IAM Alliance Vetting System
After=network.target postgresql.service

[Service]
User=www-data
Group=www-data
WorkingDirectory=/path/to/app
Environment="PATH=/path/to/virtualenv/bin"
EnvironmentFile=/path/to/app/.env
ExecStart=/path/to/virtualenv/bin/gunicorn --workers 4 --bind 127.0.0.1:5000 main:app
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

## Database Backup Configuration

Create a cron job for database backups:

```bash
# /etc/cron.d/iam-alliance-backup
0 2 * * * www-data PGPASSWORD=your_password pg_dump -U postgres iam_alliance > /path/to/backups/iam_alliance_$(date +\%Y\%m\%d).sql
0 3 * * * www-data find /path/to/backups/ -name "iam_alliance_*.sql" -mtime +14 -delete
```

## Security Contacts

For security-related issues, please contact:
- Security Team: support@rvi.iam-alliance.com
- Application Owner: admin@hq.iam-alliance.com

## Maintenance Windows

Regular maintenance windows are scheduled for:
- Every first Sunday of the month from 0200-0400 UTC