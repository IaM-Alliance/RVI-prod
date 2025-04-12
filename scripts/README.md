# IAM Alliance Application Export Scripts

This directory contains scripts to help with exporting and deploying the IAM Alliance application to a different server.

## Overview of Export Scripts

1. **master_deploy.py** - Main deployment script that coordinates the entire process
2. **setup_env.py** - Script to set up environment variables on the target server
3. **setup_systemd.py** - Script to create a systemd service for the application
4. **setup_nginx.py** - Script to set up an Nginx configuration for the application
5. **export_database.py** - Script to export the database for backup or migration
6. **verify_deployment.py** - Script to verify the deployment is working correctly

## Usage Instructions

### Quick Start

The simplest way to deploy is to use the master deployment script:

```bash
python3 scripts/master_deploy.py --target-dir /path/to/deployment --db-name iam_alliance
```

This will guide you through the entire deployment process interactively.

### Individual Scripts

If you prefer to run the steps individually:

#### 1. Environment Setup

```bash
python3 scripts/setup_env.py --db-name iam_alliance --db-user dbuser
```

#### 2. Database Export (from source server)

```bash
python3 scripts/export_database.py --env-file .env --output-file database_backup.sql
```

#### 3. Systemd Service Creation

```bash
python3 scripts/setup_systemd.py --app-dir /path/to/deployment --env-file /path/to/deployment/.env
```

#### 4. Nginx Configuration

```bash
python3 scripts/setup_nginx.py --domain app.iam-alliance.com --app-dir /path/to/deployment
```

#### 5. Verify Deployment

```bash
python3 scripts/verify_deployment.py --app-dir /path/to/deployment
```

## Manual Deployment Steps

If you prefer to deploy manually, follow these steps:

1. Copy the application files to the target server
2. Create a virtual environment and install dependencies
3. Set up the PostgreSQL database
4. Create an `.env` file with the necessary environment variables
5. Set up the directory structure (uploads/evidence)
6. Configure the systemd service
7. Configure Nginx
8. Start the application and verify it's working

Refer to the `export_guide.md` file in the root directory for detailed instructions.

## Security Considerations

- Keep the `.env` file secure (permissions set to 600)
- Ensure the database password is strong
- Set up SSL/TLS certificates for secure connections
- Review file permissions for the uploads directory
- Update the content security policy in `app.py` to match your domain

## Troubleshooting

If you encounter issues during deployment:

1. Check the logs: `sudo journalctl -u iam-alliance`
2. Verify Nginx configuration: `sudo nginx -t`
3. Check database connection using the verify script
4. Ensure all required environment variables are set
5. Check file permissions on the uploads directory

For more help, refer to the `export_guide.md` file or contact the development team.