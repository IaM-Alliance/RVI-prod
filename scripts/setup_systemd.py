#!/usr/bin/env python3
"""
Systemd Service Setup Script for IAM Alliance Application
This script creates a systemd service file to run the application.
"""

import os
import argparse
import getpass
import subprocess

SYSTEMD_SERVICE_TEMPLATE = """[Unit]
Description=IAM Alliance Flask Application
After=network.target postgresql.service

[Service]
User={user}
WorkingDirectory={app_dir}
Environment="PATH={venv_path}/bin"
EnvironmentFile={env_file}
ExecStart={venv_path}/bin/gunicorn --bind {host}:{port} --workers {workers} main:app
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""

def create_systemd_service(service_name, app_dir, env_file,
                          venv_path=None, user=None, host='127.0.0.1', 
                          port=5000, workers=3):
    """
    Create a systemd service file for the Flask application.
    
    Args:
        service_name: Name of the systemd service
        app_dir: Directory where the application is installed
        env_file: Path to the environment file
        venv_path: Path to the virtual environment
        user: User to run the service as
        host: Host to bind to
        port: Port to bind to
        workers: Number of Gunicorn worker processes
    """
    # If no virtual environment specified, use the current Python
    if not venv_path:
        venv_path = os.path.dirname(os.path.dirname(os.path.abspath(subprocess.check_output(['which', 'python3']).decode().strip())))
    
    # If no user specified, use the current user
    if not user:
        user = getpass.getuser()
    
    # Create the service file content
    service_content = SYSTEMD_SERVICE_TEMPLATE.format(
        user=user,
        app_dir=app_dir,
        venv_path=venv_path,
        env_file=env_file,
        host=host,
        port=port,
        workers=workers
    )
    
    # Build the service file path
    service_file = f"/etc/systemd/system/{service_name}.service"
    
    # Check if we have permission to write to /etc/systemd/system
    try:
        with open(service_file, 'w') as f:
            f.write(service_content)
        print(f"Systemd service file created at: {service_file}")
    except PermissionError:
        # If we don't have permission, write to the current directory
        local_file = f"{service_name}.service"
        with open(local_file, 'w') as f:
            f.write(service_content)
        print(f"Systemd service file created at: {local_file}")
        print(f"To install the service, run: sudo cp {local_file} {service_file}")
    
    # Print instructions
    print("\nTo enable and start the service:")
    print(f"sudo systemctl daemon-reload")
    print(f"sudo systemctl enable {service_name}")
    print(f"sudo systemctl start {service_name}")
    print(f"\nTo check the status:")
    print(f"sudo systemctl status {service_name}")
    print(f"\nTo view logs:")
    print(f"sudo journalctl -u {service_name}")

def main():
    parser = argparse.ArgumentParser(description='Set up systemd service for IAM Alliance Flask application')
    
    parser.add_argument('--service-name', default='iam-alliance',
                        help='Name of the systemd service (default: iam-alliance)')
    parser.add_argument('--app-dir', required=True,
                        help='Directory where the application is installed')
    parser.add_argument('--env-file', required=True,
                        help='Path to the environment file')
    parser.add_argument('--venv-path',
                        help='Path to the virtual environment')
    parser.add_argument('--user',
                        help='User to run the service as (default: current user)')
    parser.add_argument('--host', default='0.0.0.0',
                        help='Host to bind to (default: 0.0.0.0)')
    parser.add_argument('--port', default=5000, type=int,
                        help='Port to bind to (default: 5000)')
    parser.add_argument('--workers', default=3, type=int,
                        help='Number of Gunicorn worker processes (default: 3)')
    
    args = parser.parse_args()
    
    create_systemd_service(
        args.service_name,
        args.app_dir,
        args.env_file,
        args.venv_path,
        args.user,
        args.host,
        args.port,
        args.workers
    )

if __name__ == "__main__":
    main()