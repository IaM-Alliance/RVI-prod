# Guide to Export and Deploy Your Flask Application

This guide will help you export your Flask application from Replit and deploy it on a different server.

## 1. Export the Code

### Option 1: Download as ZIP
1. In Replit, click on the three dots menu (⋮) in the Files panel
2. Select "Download as ZIP"
3. Save the ZIP file to your local machine

### Option 2: Use Git
If you've connected a Git repository:
1. Push all your changes to your repository
2. Clone the repository on your target server

## 2. Set Up Your Target Environment

### Prerequisites
- Python 3.11 or compatible version
- PostgreSQL database server
- A web server (nginx, Apache) for production deployment

### Dependencies
Install these packages on your target server:

```bash
pip install email-validator>=2.2.0 flask-login>=0.6.3 flask>=3.1.0 flask-sqlalchemy>=3.1.1 gunicorn>=23.0.0 psycopg2-binary>=2.9.10 flask-wtf>=1.2.2 sqlalchemy>=2.0.40 werkzeug>=3.1.3 wtforms>=3.2.1 markupsafe>=3.0.2 requests>=2.32.3 sendgrid>=6.11.0 flask-limiter>=3.12
```

## 3. Environment Setup

Create an `.env` file on your target server with these environment variables:

```
# Database Configuration
DATABASE_URL=postgresql://username:password@localhost:5432/dbname

# Security
SESSION_SECRET=your_secure_session_key

# Matrix API (if used)
MATRIX_ADMIN_TOKEN=your_matrix_token

# Email Configuration (if used)
SMTP_RELAY_SERVER=your_smtp_server
MAILJET_API_KEY=your_mailjet_key
MAILJET_SECRET_KEY=your_mailjet_secret
```

## 4. Database Migration

1. Create a new PostgreSQL database on your target server
2. Set the DATABASE_URL environment variable to point to this database
3. Run the migration scripts:

```bash
python migrate_db.py
```

## 5. File Structure Setup

Ensure these directories exist and have proper permissions:
```bash
mkdir -p uploads/evidence
```

## 6. Production Deployment

### Using Gunicorn (as in your current setup)
Create a systemd service file (e.g., `/etc/systemd/system/iam-alliance.service`):

```
[Unit]
Description=IAM Alliance Flask Application
After=network.target postgresql.service

[Service]
User=www-data
WorkingDirectory=/path/to/your/app
Environment="PATH=/path/to/your/venv/bin"
EnvironmentFile=/path/to/your/.env
ExecStart=/path/to/your/venv/bin/gunicorn --bind 0.0.0.0:5000 --workers 3 main:app
Restart=always

[Install]
WantedBy=multi-user.target
```

### Nginx Configuration (recommended)
Create an nginx site configuration:

```
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## 7. Security Considerations

1. Set up SSL/TLS certificates (Let's Encrypt)
2. Update content security policy in `app.py` to match your new domain
3. Review file permissions for the uploads directory
4. Set secure password for the database
5. Keep environment variables secure

## 8. Start the Application

```bash
# Enable and start the service
sudo systemctl enable iam-alliance
sudo systemctl start iam-alliance

# Check status
sudo systemctl status iam-alliance
```

## 9. Regular Maintenance

1. Set up database backups
2. Monitor logs: `/var/log/syslog` or journalctl
3. Set up alerts for any failures

## 10. Additional Notes

- The application uses an uploads directory for evidence files - ensure this is properly backed up
- Matrix API integration requires valid API tokens in the new environment
- Email functionality requires proper SMTP configuration