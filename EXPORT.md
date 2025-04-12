# IAM Alliance Application Export Guide

This guide provides instructions for exporting the IAM Alliance application from Replit and deploying it to a different server.

## Quick Start

The easiest way to export and deploy this application is to use the provided scripts:

1. Copy the `scripts` directory and `export_guide.md` to your target server
2. Run the master deployment script:

```bash
python3 scripts/master_deploy.py --target-dir /path/to/deployment --db-name iam_alliance
```

3. Follow the interactive prompts to complete the deployment

## What's Included

### Deployment Scripts

The `scripts` directory contains several helper scripts to streamline the deployment process:

- **master_deploy.py**: Main script that coordinates the entire deployment process
- **setup_env.py**: Creates the environment file with necessary configuration
- **setup_systemd.py**: Sets up a systemd service to run the application
- **setup_nginx.py**: Creates an Nginx configuration for the application
- **export_database.py**: Exports the database for backup or migration
- **verify_deployment.py**: Verifies the deployment is working correctly

### Detailed Guide

The `export_guide.md` file provides comprehensive manual instructions for deploying the application if you prefer to handle the process step by step.

## Required Environment Variables

The application requires these environment variables:

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

## Dependencies

The application requires:

- Python 3.11 or compatible version
- PostgreSQL database
- Nginx web server (recommended)
- Required Python packages (installed automatically by the scripts)

## Directory Structure

The following directories are used by the application:

- **uploads/evidence**: Storage for evidence files
- **static**: Static assets (CSS, JS, etc.)
- **templates**: HTML templates for the application

## Deployment Process

The complete deployment process involves:

1. Setting up the target environment
2. Copying the application code
3. Creating a virtual environment
4. Installing dependencies
5. Setting up the PostgreSQL database
6. Running database migrations
7. Configuring the application environment
8. Setting up systemd service for process management
9. Configuring Nginx for web access
10. Securing the deployment with SSL/TLS

For detailed instructions on each step, see the `export_guide.md` file or run the deployment scripts.

## Troubleshooting

If you encounter issues during deployment:

1. Check the application logs: `sudo journalctl -u iam-alliance`
2. Verify the database connection
3. Check that all environment variables are correctly set
4. Ensure file permissions are correct, especially for uploads
5. Verify Nginx configuration: `sudo nginx -t`

## Security Recommendations

- Always use HTTPS with valid SSL certificates
- Keep the `.env` file secure with restricted permissions (chmod 600)
- Set strong passwords for the database
- Regularly backup the database and uploaded files
- Update the content security policy to match your domain
- Consider setting up fail2ban for additional security