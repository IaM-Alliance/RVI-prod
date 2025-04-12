#!/usr/bin/env python3
"""
Master Deployment Script for IAM Alliance Application
This script orchestrates the entire deployment process for the application.
"""

import os
import sys
import argparse
import subprocess
import shutil
import getpass
import datetime
import time
from urllib.parse import urlparse

# ANSI color codes for output formatting
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_header(message):
    """Print a formatted header message"""
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*80}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD} {message}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{'='*80}{Colors.ENDC}\n")

def print_step(step, message):
    """Print a formatted step message"""
    print(f"{Colors.BLUE}{Colors.BOLD}[Step {step}]{Colors.ENDC} {message}")

def print_success(message):
    """Print a formatted success message"""
    print(f"{Colors.GREEN}{Colors.BOLD}[✓] {message}{Colors.ENDC}")

def print_warning(message):
    """Print a formatted warning message"""
    print(f"{Colors.YELLOW}{Colors.BOLD}[!] {message}{Colors.ENDC}")

def print_error(message):
    """Print a formatted error message"""
    print(f"{Colors.RED}{Colors.BOLD}[✗] {message}{Colors.ENDC}")

def run_command(cmd, env=None, capture_output=True, check=True):
    """Run a command and handle exceptions"""
    try:
        if capture_output:
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                env=env,
                check=check
            )
            return result
        else:
            # Stream output to console
            subprocess.run(cmd, env=env, check=check)
            return None
    except subprocess.CalledProcessError as e:
        print_error(f"Command failed with exit code {e.returncode}")
        if e.stdout:
            print(f"Standard output:\n{e.stdout}")
        if e.stderr:
            print(f"Standard error:\n{e.stderr}")
        return e
    except Exception as e:
        print_error(f"Exception while running command: {str(e)}")
        return None

def check_prerequisites():
    """Check if all required tools are installed"""
    print_step(1, "Checking prerequisites...")
    
    requirements = [
        ('python3', 'Python 3.x is required'),
        ('pip', 'pip package manager is required'),
        ('git', 'Git version control is required'),
        ('pg_dump', 'PostgreSQL client tools are required'),
        ('gunicorn', 'Gunicorn is required')
    ]
    
    success = True
    for cmd, msg in requirements:
        try:
            subprocess.run(['which', cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            print(f"  {Colors.GREEN}✓{Colors.ENDC} {cmd} is installed")
        except subprocess.CalledProcessError:
            print(f"  {Colors.RED}✗{Colors.ENDC} {cmd} is not installed - {msg}")
            success = False
    
    return success

def clone_or_copy_repository(source, target_dir):
    """Clone a repository or copy the code to the target directory"""
    print_step(2, f"Preparing code in {target_dir}...")
    
    # Check if source is a git repository URL
    is_git_url = source.startswith('http') and (
        source.endswith('.git') or 'github.com' in source or 'gitlab.com' in source
    )
    
    if is_git_url:
        print(f"Cloning repository from {source}...")
        run_command(['git', 'clone', source, target_dir], capture_output=False)
        print_success(f"Repository cloned to {target_dir}")
    else:
        # Source is a local directory
        if not os.path.exists(source):
            print_error(f"Source directory {source} does not exist")
            return False
        
        # Create target directory if it doesn't exist
        os.makedirs(target_dir, exist_ok=True)
        
        # Copy files
        print(f"Copying files from {source} to {target_dir}...")
        excluded = ['.git', '__pycache__', 'venv', '.env', '*.pyc', '.replit']
        
        for item in os.listdir(source):
            # Skip excluded items
            skip = False
            for pattern in excluded:
                if pattern.startswith('*'):
                    if item.endswith(pattern[1:]):
                        skip = True
                        break
                elif item == pattern:
                    skip = True
                    break
            
            if skip:
                continue
                
            src_path = os.path.join(source, item)
            dst_path = os.path.join(target_dir, item)
            
            if os.path.isdir(src_path):
                shutil.copytree(src_path, dst_path, dirs_exist_ok=True)
            else:
                shutil.copy2(src_path, dst_path)
        
        print_success(f"Files copied to {target_dir}")
    
    return True

def setup_virtual_environment(target_dir):
    """Set up a Python virtual environment"""
    print_step(3, "Setting up virtual environment...")
    
    venv_dir = os.path.join(target_dir, 'venv')
    
    # Create virtual environment
    run_command(['python3', '-m', 'venv', venv_dir], capture_output=False)
    
    # Get the path to pip in the virtual environment
    if os.name == 'nt':  # Windows
        pip_path = os.path.join(venv_dir, 'Scripts', 'pip')
    else:  # Unix-like
        pip_path = os.path.join(venv_dir, 'bin', 'pip')
    
    # Upgrade pip
    run_command([pip_path, 'install', '--upgrade', 'pip'], capture_output=False)
    
    # Install application dependencies from pyproject.toml if it exists, otherwise use requirements
    if os.path.exists(os.path.join(target_dir, 'pyproject.toml')):
        run_command([pip_path, 'install', '.'], cwd=target_dir, capture_output=False)
    elif os.path.exists(os.path.join(target_dir, 'requirements.txt')):
        run_command([pip_path, 'install', '-r', 'requirements.txt'], cwd=target_dir, capture_output=False)
    else:
        # Generate requirements from script
        requirements = [
            'email-validator>=2.2.0',
            'flask-login>=0.6.3',
            'flask>=3.1.0',
            'flask-sqlalchemy>=3.1.1',
            'gunicorn>=23.0.0',
            'psycopg2-binary>=2.9.10',
            'flask-wtf>=1.2.2',
            'sqlalchemy>=2.0.40',
            'werkzeug>=3.1.3',
            'wtforms>=3.2.1',
            'markupsafe>=3.0.2',
            'requests>=2.32.3',
            'sendgrid>=6.11.0',
            'flask-limiter>=3.12',
            'python-dotenv>=1.0.0'
        ]
        
        req_file = os.path.join(target_dir, 'requirements.txt')
        with open(req_file, 'w') as f:
            f.write('\n'.join(requirements))
        
        run_command([pip_path, 'install', '-r', 'requirements.txt'], cwd=target_dir, capture_output=False)
    
    print_success("Virtual environment setup complete")
    return venv_dir

def setup_environment_file(target_dir, db_name, db_user=None, db_password=None, db_host='localhost'):
    """Set up the environment file with database and other configuration"""
    print_step(4, "Setting up environment file...")
    
    # Default database credentials if not provided
    if not db_user:
        db_user = input("Enter database username: ")
    
    if not db_password:
        db_password = getpass.getpass("Enter database password: ")
    
    # Generate a secure secret key
    secret_key = os.urandom(24).hex()
    
    # Create the environment file
    env_file = os.path.join(target_dir, '.env')
    
    with open(env_file, 'w') as f:
        f.write(f"# Database Configuration\n")
        f.write(f"DATABASE_URL=postgresql://{db_user}:{db_password}@{db_host}/{db_name}\n\n")
        f.write(f"# Security\n")
        f.write(f"SESSION_SECRET={secret_key}\n\n")
        
        # Ask about Matrix API token
        matrix_token = input("Enter Matrix API token (leave blank if not used): ")
        if matrix_token:
            f.write(f"# Matrix API\n")
            f.write(f"MATRIX_ADMIN_TOKEN={matrix_token}\n\n")
        
        # Ask about SMTP configuration
        smtp_server = input("Enter SMTP server (leave blank if not used): ")
        if smtp_server:
            f.write(f"# Email Configuration\n")
            f.write(f"SMTP_RELAY_SERVER={smtp_server}\n")
            
            mailjet_key = input("Enter Mailjet API key (leave blank if not used): ")
            if mailjet_key:
                f.write(f"MAILJET_API_KEY={mailjet_key}\n")
                
                mailjet_secret = getpass.getpass("Enter Mailjet secret key: ")
                if mailjet_secret:
                    f.write(f"MAILJET_SECRET_KEY={mailjet_secret}\n")
    
    # Set appropriate permissions on the .env file
    os.chmod(env_file, 0o600)
    
    print_success(f"Environment file created at {env_file}")
    return env_file

def setup_postgresql_database(db_name, db_user, db_password, db_host='localhost'):
    """Set up the PostgreSQL database"""
    print_step(5, "Setting up PostgreSQL database...")
    
    # Check if PostgreSQL is installed
    try:
        run_command(['which', 'psql'], capture_output=True, check=True)
    except Exception:
        print_error("PostgreSQL client tools are not installed")
        print("Please install PostgreSQL client tools and try again")
        return False
    
    # Default database superuser is postgres
    postgres_user = input("Enter PostgreSQL superuser (default: postgres): ") or "postgres"
    
    # Create the database user if it doesn't exist
    print(f"Creating database user {db_user} if it doesn't exist...")
    create_user_cmd = f"CREATE USER {db_user} WITH PASSWORD '{db_password}';"
    
    try:
        run_command([
            'sudo', '-u', postgres_user, 'psql', '-c', create_user_cmd
        ], capture_output=True)
    except Exception as e:
        print_warning(f"Could not create user (may already exist): {str(e)}")
    
    # Create the database if it doesn't exist
    print(f"Creating database {db_name} if it doesn't exist...")
    create_db_cmd = f"CREATE DATABASE {db_name} WITH OWNER {db_user} ENCODING 'UTF8';"
    
    try:
        run_command([
            'sudo', '-u', postgres_user, 'psql', '-c', create_db_cmd
        ], capture_output=True)
    except Exception as e:
        print_warning(f"Could not create database (may already exist): {str(e)}")
    
    # Grant privileges
    print(f"Granting privileges to {db_user} on {db_name}...")
    grant_cmd = f"GRANT ALL PRIVILEGES ON DATABASE {db_name} TO {db_user};"
    
    try:
        run_command([
            'sudo', '-u', postgres_user, 'psql', '-c', grant_cmd
        ], capture_output=True)
    except Exception as e:
        print_warning(f"Could not grant privileges: {str(e)}")
    
    print_success(f"Database setup complete for {db_name}")
    return True

def run_database_migrations(target_dir, venv_dir):
    """Run database migrations"""
    print_step(6, "Running database migrations...")
    
    # Get the path to python in the virtual environment
    if os.name == 'nt':  # Windows
        python_path = os.path.join(venv_dir, 'Scripts', 'python')
    else:  # Unix-like
        python_path = os.path.join(venv_dir, 'bin', 'python')
    
    # Check for migration scripts
    migration_script = None
    for candidate in ['migrate_db.py', 'migrate_db_direct.py']:
        if os.path.exists(os.path.join(target_dir, candidate)):
            migration_script = candidate
            break
    
    if migration_script:
        print(f"Running migration script: {migration_script}")
        run_command([python_path, migration_script], cwd=target_dir, capture_output=False, check=False)
    else:
        print_warning("No migration script found, manual database setup may be required")
    
    print_success("Database migration complete")
    return True

def setup_directory_structure(target_dir):
    """Set up required directories"""
    print_step(7, "Setting up directory structure...")
    
    # Create uploads directory for evidence files
    uploads_dir = os.path.join(target_dir, 'uploads')
    evidence_dir = os.path.join(uploads_dir, 'evidence')
    
    os.makedirs(uploads_dir, exist_ok=True)
    os.makedirs(evidence_dir, exist_ok=True)
    
    # Set appropriate permissions if not on Windows
    if os.name != 'nt':
        run_command(['chmod', '-R', '755', uploads_dir])
    
    print_success("Directory structure set up")
    return True

def create_systemd_service(target_dir, venv_dir, service_name='iam-alliance'):
    """Create a systemd service file"""
    print_step(8, "Creating systemd service...")
    
    # Check if we're on a system with systemd
    try:
        run_command(['which', 'systemctl'], capture_output=True, check=True)
    except Exception:
        print_warning("systemd not found, skipping service creation")
        return False
    
    # Get the current user
    current_user = getpass.getuser()
    
    # Create service file content
    service_content = f"""[Unit]
Description=IAM Alliance Flask Application
After=network.target postgresql.service

[Service]
User={current_user}
WorkingDirectory={target_dir}
Environment="PATH={venv_dir}/bin"
EnvironmentFile={os.path.join(target_dir, '.env')}
ExecStart={os.path.join(venv_dir, 'bin', 'gunicorn')} --bind 0.0.0.0:5000 --workers 3 main:app
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""
    
    # Save service file
    service_file = f"{service_name}.service"
    with open(service_file, 'w') as f:
        f.write(service_content)
    
    print(f"Service file created: {service_file}")
    print(f"To install and start the service:")
    print(f"sudo cp {service_file} /etc/systemd/system/")
    print(f"sudo systemctl daemon-reload")
    print(f"sudo systemctl enable {service_name}")
    print(f"sudo systemctl start {service_name}")
    
    print_success("Systemd service file created")
    return True

def create_nginx_config(target_dir, domain, service_name='iam-alliance'):
    """Create an nginx configuration file"""
    print_step(9, "Creating Nginx configuration...")
    
    # Get static directory path
    static_dir = os.path.join(target_dir, 'static')
    
    # Create nginx configuration
    nginx_content = f"""server {{
    listen 80;
    server_name {domain};
    
    # Application location
    location / {{
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }}
    
    # Static files
    location /static/ {{
        alias {static_dir}/;
        expires 30d;
    }}
    
    # Security headers
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    
    # Logging
    access_log /var/log/nginx/{service_name}_access.log;
    error_log /var/log/nginx/{service_name}_error.log;
}}
"""
    
    # Save nginx configuration
    nginx_file = f"{service_name}.nginx.conf"
    with open(nginx_file, 'w') as f:
        f.write(nginx_content)
    
    print(f"Nginx config created: {nginx_file}")
    print(f"To install the nginx configuration:")
    print(f"sudo cp {nginx_file} /etc/nginx/sites-available/{service_name}")
    print(f"sudo ln -s /etc/nginx/sites-available/{service_name} /etc/nginx/sites-enabled/")
    print(f"sudo nginx -t")
    print(f"sudo systemctl reload nginx")
    
    # Ask if they want to set up SSL with Let's Encrypt
    ssl_setup = input("Do you want instructions for setting up SSL with Let's Encrypt? (y/n): ")
    if ssl_setup.lower() == 'y':
        print("\nTo set up SSL with Let's Encrypt:")
        print(f"sudo apt install certbot python3-certbot-nginx")
        print(f"sudo certbot --nginx -d {domain}")
    
    print_success("Nginx configuration created")
    return True

def verify_deployment(target_dir, venv_dir):
    """Verify the deployment"""
    print_step(10, "Verifying deployment...")
    
    # Get the path to python in the virtual environment
    if os.name == 'nt':  # Windows
        python_path = os.path.join(venv_dir, 'Scripts', 'python')
    else:  # Unix-like
        python_path = os.path.join(venv_dir, 'bin', 'python')
    
    # Check if the .env file exists
    env_file = os.path.join(target_dir, '.env')
    if not os.path.exists(env_file):
        print_error(f"Environment file not found: {env_file}")
        return False
    
    # Check directory structure
    uploads_dir = os.path.join(target_dir, 'uploads')
    evidence_dir = os.path.join(uploads_dir, 'evidence')
    if not os.path.exists(uploads_dir) or not os.path.exists(evidence_dir):
        print_error("Required directories not found")
        return False
    
    # Check if main application files exist
    required_files = ['app.py', 'main.py', 'models.py']
    for file in required_files:
        if not os.path.exists(os.path.join(target_dir, file)):
            print_error(f"Required file not found: {file}")
            return False
    
    print_success("Deployment verification complete")
    return True

def main():
    parser = argparse.ArgumentParser(description='Deploy IAM Alliance Flask application')
    
    parser.add_argument('--source', default='.',
                        help='Source code directory or Git repository URL')
    parser.add_argument('--target-dir', required=True,
                        help='Target directory for deployment')
    parser.add_argument('--db-name', default='iam_alliance',
                        help='PostgreSQL database name (default: iam_alliance)')
    parser.add_argument('--db-user',
                        help='PostgreSQL database user')
    parser.add_argument('--db-password',
                        help='PostgreSQL database password')
    parser.add_argument('--db-host', default='localhost',
                        help='PostgreSQL database host (default: localhost)')
    parser.add_argument('--service-name', default='iam-alliance',
                        help='Name for systemd service and nginx config (default: iam-alliance)')
    parser.add_argument('--domain',
                        help='Domain name for nginx configuration')
    parser.add_argument('--skip-steps', type=str,
                        help='Comma-separated list of steps to skip (e.g. "systemd,nginx")')
    
    args = parser.parse_args()
    
    # Parse steps to skip
    skip_steps = []
    if args.skip_steps:
        skip_steps = [step.strip() for step in args.skip_steps.split(',')]
    
    # Start deployment
    print_header("IAM Alliance Deployment Script")
    print("Starting deployment process...")
    
    # Check prerequisites
    if 'prereq' not in skip_steps:
        if not check_prerequisites():
            print_error("Prerequisites check failed, please install missing tools")
            return
    
    # Clone or copy repository
    if 'clone' not in skip_steps:
        if not clone_or_copy_repository(args.source, args.target_dir):
            print_error("Failed to prepare code")
            return
    
    # Set up virtual environment
    if 'venv' not in skip_steps:
        venv_dir = setup_virtual_environment(args.target_dir)
    else:
        # Assume venv is in standard location
        venv_dir = os.path.join(args.target_dir, 'venv')
    
    # Set up environment file
    if 'env' not in skip_steps:
        env_file = setup_environment_file(
            args.target_dir,
            args.db_name,
            args.db_user,
            args.db_password,
            args.db_host
        )
    
    # Set up database
    if 'database' not in skip_steps:
        # If db_user or db_password not provided, prompt for them
        db_user = args.db_user
        db_password = args.db_password
        
        if not db_user:
            db_user = input("Enter database username: ")
        
        if not db_password:
            db_password = getpass.getpass("Enter database password: ")
        
        if not setup_postgresql_database(args.db_name, db_user, db_password, args.db_host):
            print_warning("Database setup had issues, continuing but deployment may fail")
    
    # Set up directory structure
    if 'dirs' not in skip_steps:
        setup_directory_structure(args.target_dir)
    
    # Run database migrations
    if 'migrations' not in skip_steps:
        run_database_migrations(args.target_dir, venv_dir)
    
    # Create systemd service
    if 'systemd' not in skip_steps:
        create_systemd_service(args.target_dir, venv_dir, args.service_name)
    
    # Create nginx configuration
    if 'nginx' not in skip_steps:
        if args.domain:
            create_nginx_config(args.target_dir, args.domain, args.service_name)
        else:
            domain = input("Enter domain name for nginx configuration (e.g., app.iam-alliance.com): ")
            if domain:
                create_nginx_config(args.target_dir, domain, args.service_name)
            else:
                print_warning("No domain provided, skipping nginx configuration")
    
    # Verify deployment
    if 'verify' not in skip_steps:
        verify_deployment(args.target_dir, venv_dir)
    
    # Final instructions
    print_header("Deployment Complete")
    print(f"Application deployed to: {args.target_dir}")
    print("\nNext steps:")
    print(f"1. Check the environment file at {os.path.join(args.target_dir, '.env')}")
    print(f"2. Install the systemd service and start the application")
    print(f"3. Configure and reload nginx")
    print(f"4. Set up SSL with Let's Encrypt")
    print(f"5. Test the application")

if __name__ == "__main__":
    main()