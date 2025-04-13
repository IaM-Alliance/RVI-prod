#!/usr/bin/env python3
"""
Environment Setup Script for IAM Alliance Application
This script helps set up the necessary environment variables for deployment.
"""

import os
import secrets
import argparse
import getpass

def generate_secret_key():
    """Generate a secure secret key for Flask sessions"""
    return secrets.token_hex(32)

def create_env_file(env_file_path, db_user, db_pass, db_name, db_host='localhost', 
                    db_port='5432', matrix_token=None, mailjet_key=None, mailjet_secret=None):
    """Create a .env file with the necessary environment variables"""
    
    # Create the directory if it doesn't exist
    os.makedirs(os.path.dirname(os.path.abspath(env_file_path)), exist_ok=True)
    
    # Generate session secret
    session_secret = generate_secret_key()
    
    # Create the environment variables
    env_vars = [
        "# Database Configuration",
        f"DATABASE_URL=postgresql://{db_user}:{db_pass}@{db_host}:{db_port}/{db_name}",
        "",
        "# Security",
        f"SESSION_SECRET={session_secret}",
        ""
    ]
    
    # Add Matrix token if provided
    if matrix_token:
        env_vars.extend([
            "# Matrix API",
            f"MATRIX_ADMIN_TOKEN={matrix_token}",
            ""
        ])
    
    # Add email configuration if provided
    if mailjet_key or mailjet_secret:
        env_vars.append("# Email Configuration (Mailjet SMTP)")
        
        if mailjet_key:
            env_vars.append(f"MAILJET_API_KEY={mailjet_key}")
        
        if mailjet_secret:
            env_vars.append(f"MAILJET_SECRET_KEY={mailjet_secret}")
    
    # Write the file
    with open(env_file_path, 'w') as f:
        f.write('\n'.join(env_vars))
    
    print(f"Environment file created at: {env_file_path}")
    print("IMPORTANT: Keep this file secure as it contains sensitive information.")
    
    # Set the file permissions to be readable only by the owner
    os.chmod(env_file_path, 0o600)
    print(f"File permissions set to 600 (owner readable/writable only)")

def main():
    parser = argparse.ArgumentParser(description='Set up environment for IAM Alliance Flask application')
    
    parser.add_argument('--env-file', default='.env',
                        help='Path to the environment file to create (default: .env)')
    
    # Database arguments
    parser.add_argument('--db-name', required=True,
                        help='PostgreSQL database name')
    parser.add_argument('--db-user', required=True,
                        help='PostgreSQL database user')
    parser.add_argument('--db-host', default='localhost',
                        help='PostgreSQL database host (default: localhost)')
    parser.add_argument('--db-port', default='5432',
                        help='PostgreSQL database port (default: 5432)')
    
    # Optional configuration
    parser.add_argument('--matrix-token',
                        help='Matrix admin token for API access')
    parser.add_argument('--mailjet-key',
                        help='Mailjet API key for email sending')
    parser.add_argument('--mailjet-secret',
                        help='Mailjet API secret for email sending')
    
    args = parser.parse_args()
    
    # Ask for the database password securely
    db_pass = getpass.getpass(f"Enter password for database user '{args.db_user}': ")
    
    # Create the environment file
    create_env_file(
        args.env_file,
        args.db_user,
        db_pass,
        args.db_name,
        args.db_host,
        args.db_port,
        args.matrix_token,
        args.smtp_server,
        args.mailjet_key,
        args.mailjet_secret
    )
    
    print("\nEnvironment setup completed successfully!")
    print("Next steps:")
    print("1. Review the generated .env file to ensure all values are correct")
    print("2. Set up the database using the migration script")
    print("3. Configure your web server to serve the application")

if __name__ == "__main__":
    main()