#!/usr/bin/env python3
"""
Deployment Verification Script for IAM Alliance Application
This script tests various aspects of the deployment to ensure it's working correctly.
"""

import os
import sys
import argparse
import requests
import subprocess
import socket
import psycopg2
from urllib.parse import urlparse
from dotenv import load_dotenv

def check_database_connection(database_url):
    """Check if the database is accessible"""
    print("Checking database connection...")
    
    try:
        # Parse the database URL
        parsed = urlparse(database_url)
        dbname = parsed.path[1:]  # Remove leading slash
        user = parsed.username
        password = parsed.password
        host = parsed.hostname
        port = parsed.port
        
        # Connect to the database
        conn = psycopg2.connect(
            dbname=dbname,
            user=user,
            password=password,
            host=host,
            port=port
        )
        
        # Get the database version
        cursor = conn.cursor()
        cursor.execute('SELECT version();')
        version = cursor.fetchone()[0]
        
        print(f"[✓] Database connection successful")
        print(f"    Database version: {version}")
        
        # Get table count
        cursor.execute("""
            SELECT COUNT(*) FROM information_schema.tables 
            WHERE table_schema = 'public';
        """)
        table_count = cursor.fetchone()[0]
        print(f"    Number of tables: {table_count}")
        
        # Check for specific tables we expect
        for table in ['user', 'vetting_form', 'matrix_token', 'audit_log']:
            cursor.execute(f"""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_schema = 'public' 
                    AND table_name = '{table}'
                );
            """)
            exists = cursor.fetchone()[0]
            print(f"    Table '{table}': {'[✓] Exists' if exists else '[!] Missing'}")
        
        cursor.close()
        conn.close()
        return True
    except Exception as e:
        print(f"[✗] Database connection failed: {str(e)}")
        return False

def check_web_server(url, expected_status=200):
    """Check if the web server is responding"""
    print(f"\nChecking web server at {url}...")
    
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == expected_status:
            print(f"[✓] Web server is running")
            print(f"    Status code: {response.status_code}")
            return True
        else:
            print(f"[✗] Web server returned unexpected status code: {response.status_code}")
            return False
    except requests.RequestException as e:
        print(f"[✗] Web server check failed: {str(e)}")
        return False

def check_system_service(service_name):
    """Check if the systemd service is running"""
    print(f"\nChecking systemd service '{service_name}'...")
    
    try:
        result = subprocess.run(
            ['systemctl', 'is-active', service_name],
            capture_output=True,
            text=True
        )
        
        if result.stdout.strip() == 'active':
            print(f"[✓] Service '{service_name}' is running")
            return True
        else:
            print(f"[✗] Service '{service_name}' is not running")
            print(f"    Status: {result.stdout.strip()}")
            return False
    except Exception as e:
        print(f"[✗] Service check failed: {str(e)}")
        return False

def check_file_permissions(app_dir):
    """Check if file permissions are set correctly"""
    print("\nChecking file permissions...")
    
    uploads_dir = os.path.join(app_dir, 'uploads')
    evidence_dir = os.path.join(uploads_dir, 'evidence')
    env_file = os.path.join(app_dir, '.env')
    
    # Check uploads directories
    if os.path.exists(uploads_dir):
        uploads_mode = oct(os.stat(uploads_dir).st_mode)[-3:]
        print(f"    uploads directory: mode {uploads_mode}")
    else:
        print(f"[✗] uploads directory does not exist")
    
    if os.path.exists(evidence_dir):
        evidence_mode = oct(os.stat(evidence_dir).st_mode)[-3:]
        print(f"    evidence directory: mode {evidence_mode}")
    else:
        print(f"[✗] evidence directory does not exist")
    
    # Check .env file
    if os.path.exists(env_file):
        env_mode = oct(os.stat(env_file).st_mode)[-3:]
        print(f"    .env file: mode {env_mode}")
        if env_mode != '600':
            print(f"[!] Warning: .env file should have mode 600, not {env_mode}")
    else:
        print(f"[✗] .env file does not exist")

def check_environment_variables():
    """Check if required environment variables are set"""
    print("\nChecking environment variables...")
    
    required_vars = [
        'DATABASE_URL',
        'SESSION_SECRET'
    ]
    
    optional_vars = [
        'MATRIX_ADMIN_TOKEN',
        'SMTP_RELAY_SERVER',
        'MAILJET_API_KEY',
        'MAILJET_SECRET_KEY'
    ]
    
    # Check required variables
    missing = []
    for var in required_vars:
        if os.environ.get(var):
            print(f"[✓] {var} is set")
        else:
            print(f"[✗] {var} is missing")
            missing.append(var)
    
    # Check optional variables
    for var in optional_vars:
        if os.environ.get(var):
            print(f"[✓] {var} is set")
        else:
            print(f"[!] {var} is not set (optional)")
    
    return len(missing) == 0

def main():
    parser = argparse.ArgumentParser(description='Verify the IAM Alliance deployment')
    
    parser.add_argument('--app-dir', default=os.getcwd(),
                        help='Directory where the application is installed')
    parser.add_argument('--service-name', default='iam-alliance',
                        help='Name of the systemd service')
    parser.add_argument('--url', default='http://localhost:5000',
                        help='URL to check the web server')
    parser.add_argument('--env-file', default='.env',
                        help='Path to the .env file')
    
    args = parser.parse_args()
    
    # Load environment variables from .env file
    env_path = os.path.join(args.app_dir, args.env_file)
    if os.path.exists(env_path):
        load_dotenv(env_path)
    
    print("=== IAM Alliance Deployment Verification ===\n")
    
    # Check environment variables
    if not check_environment_variables():
        print("\n[!] Some required environment variables are missing")
    
    # Check database connection
    database_url = os.environ.get('DATABASE_URL')
    if database_url:
        check_database_connection(database_url)
    else:
        print("[✗] DATABASE_URL environment variable is not set, skipping database check")
    
    # Check web server
    check_web_server(args.url)
    
    # Check file permissions
    check_file_permissions(args.app_dir)
    
    # Check system service if not running as root
    if os.geteuid() == 0:
        check_system_service(args.service_name)
    else:
        print(f"\n[!] Not running as root, skipping service check for '{args.service_name}'")
        print("    Run with sudo to check the service status")
    
    print("\n=== Verification Complete ===")

if __name__ == "__main__":
    main()