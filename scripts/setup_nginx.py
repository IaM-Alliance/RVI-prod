#!/usr/bin/env python3
"""
Nginx Configuration Setup Script for IAM Alliance Application
This script creates an Nginx site configuration for the application.
"""

import os
import argparse
import subprocess

NGINX_CONFIG_TEMPLATE = """server {{
    listen 80;
    server_name {domain};
    
    # Application location
    location / {{
        proxy_pass http://{proxy_host}:{proxy_port};
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
    
    # Evidence files (if accessible via nginx)
    location /uploads/ {{
        internal; # Prevents direct access, files must be served through Flask
    }}
    
    # Security headers
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    
    # Logging
    access_log {log_dir}/access.log;
    error_log {log_dir}/error.log;
}}
"""

NGINX_SSL_CONFIG_TEMPLATE = """server {{
    listen 80;
    server_name {domain};
    
    # Redirect all HTTP traffic to HTTPS
    location / {{
        return 301 https://$host$request_uri;
    }}
}}

server {{
    listen 443 ssl;
    server_name {domain};
    
    # SSL Configuration
    ssl_certificate {ssl_cert};
    ssl_certificate_key {ssl_key};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    
    # HSTS (comment out if testing)
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # Application location
    location / {{
        proxy_pass http://{proxy_host}:{proxy_port};
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
    
    # Evidence files (if accessible via nginx)
    location /uploads/ {{
        internal; # Prevents direct access, files must be served through Flask
    }}
    
    # Security headers
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
    
    # Logging
    access_log {log_dir}/access.log;
    error_log {log_dir}/error.log;
}}
"""

def create_nginx_config(config_name, domain, app_dir, use_ssl=False,
                        proxy_host='127.0.0.1', proxy_port=5000,
                        ssl_cert=None, ssl_key=None, log_dir=None):
    """
    Create an Nginx site configuration for the Flask application.
    
    Args:
        config_name: Name of the Nginx config file (without .conf)
        domain: Domain name for the site
        app_dir: Directory where the application is installed
        use_ssl: Whether to use SSL/TLS
        proxy_host: Host where the Flask app is running
        proxy_port: Port where the Flask app is running
        ssl_cert: Path to SSL certificate file
        ssl_key: Path to SSL private key file
        log_dir: Directory for Nginx logs
    """
    # Set static directory
    static_dir = os.path.join(app_dir, 'static')
    
    # Set log directory
    if not log_dir:
        log_dir = '/var/log/nginx'
    
    # Choose template based on SSL setting
    if use_ssl:
        if not ssl_cert or not ssl_key:
            print("ERROR: SSL certificate and key paths are required when use_ssl is enabled")
            return
        
        config_content = NGINX_SSL_CONFIG_TEMPLATE.format(
            domain=domain,
            proxy_host=proxy_host,
            proxy_port=proxy_port,
            static_dir=static_dir,
            ssl_cert=ssl_cert,
            ssl_key=ssl_key,
            log_dir=log_dir
        )
    else:
        config_content = NGINX_CONFIG_TEMPLATE.format(
            domain=domain,
            proxy_host=proxy_host,
            proxy_port=proxy_port,
            static_dir=static_dir,
            log_dir=log_dir
        )
    
    # Build the config file path
    nginx_available = '/etc/nginx/sites-available'
    nginx_enabled = '/etc/nginx/sites-enabled'
    
    config_file = f"{config_name}.conf"
    nginx_config_path = os.path.join(nginx_available, config_file)
    
    # Check if we have permission to write to nginx directories
    try:
        # Try to write to sites-available
        os.makedirs(nginx_available, exist_ok=True)
        with open(nginx_config_path, 'w') as f:
            f.write(config_content)
        print(f"Nginx config created at: {nginx_config_path}")
        
        # Create symlink in sites-enabled
        try:
            os.makedirs(nginx_enabled, exist_ok=True)
            nginx_enabled_path = os.path.join(nginx_enabled, config_file)
            if os.path.exists(nginx_enabled_path):
                os.remove(nginx_enabled_path)
            os.symlink(nginx_config_path, nginx_enabled_path)
            print(f"Nginx symlink created at: {nginx_enabled_path}")
        except PermissionError:
            print(f"Unable to create symlink. To enable the site, run: sudo ln -s {nginx_config_path} {nginx_enabled_path}")
    except PermissionError:
        # If we don't have permission, write to the current directory
        with open(config_file, 'w') as f:
            f.write(config_content)
        print(f"Nginx config created at: {config_file}")
        print(f"To install the config, run: sudo cp {config_file} {nginx_config_path}")
        print(f"To enable the site, run: sudo ln -s {nginx_config_path} {os.path.join(nginx_enabled, config_file)}")
    
    # Print instructions
    print("\nTo test the Nginx configuration:")
    print("sudo nginx -t")
    print("\nTo reload Nginx:")
    print("sudo systemctl reload nginx")
    
    # Print SSL instructions if applicable
    if use_ssl:
        print("\nMake sure your SSL certificates are properly set up.")
        print("If you need SSL certificates, you can use Let's Encrypt:")
        print("sudo apt install certbot python3-certbot-nginx")
        print(f"sudo certbot --nginx -d {domain}")

def main():
    parser = argparse.ArgumentParser(description='Set up Nginx configuration for IAM Alliance Flask application')
    
    parser.add_argument('--config-name', default='iam-alliance',
                        help='Name of the Nginx config file (default: iam-alliance)')
    parser.add_argument('--domain', required=True,
                        help='Domain name for the site (e.g., app.iam-alliance.com)')
    parser.add_argument('--app-dir', required=True,
                        help='Directory where the application is installed')
    parser.add_argument('--use-ssl', action='store_true',
                        help='Configure for HTTPS with SSL/TLS')
    parser.add_argument('--proxy-host', default='127.0.0.1',
                        help='Host where the Flask app is running (default: 127.0.0.1)')
    parser.add_argument('--proxy-port', default=5000, type=int,
                        help='Port where the Flask app is running (default: 5000)')
    parser.add_argument('--ssl-cert',
                        help='Path to SSL certificate file (required with --use-ssl)')
    parser.add_argument('--ssl-key',
                        help='Path to SSL private key file (required with --use-ssl)')
    parser.add_argument('--log-dir',
                        help='Directory for Nginx logs (default: /var/log/nginx)')
    
    args = parser.parse_args()
    
    create_nginx_config(
        args.config_name,
        args.domain,
        args.app_dir,
        args.use_ssl,
        args.proxy_host,
        args.proxy_port,
        args.ssl_cert,
        args.ssl_key,
        args.log_dir
    )

if __name__ == "__main__":
    main()