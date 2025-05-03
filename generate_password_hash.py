#!/usr/bin/env python3
"""
Script to generate password hashes for the RVI-Alliance Vetting System database.
This script creates Werkzeug password hashes compatible with the application.
"""

import sys
import argparse
from werkzeug.security import generate_password_hash

def main():
    parser = argparse.ArgumentParser(description='Generate a password hash for database use')
    parser.add_argument('password', nargs='?', help='Password to hash (if not provided, you will be prompted)')
    parser.add_argument('--method', default='scrypt', 
                        help='Hashing method (default: scrypt)')
    parser.add_argument('--salt-length', type=int, default=16, 
                        help='Salt length (default: 16)')
    parser.add_argument('--quiet', '-q', action='store_true', 
                        help='Only output the hash')
    
    args = parser.parse_args()
    
    # Get password securely if not provided as argument
    password = args.password
    if password is None:
        import getpass
        password = getpass.getpass('Enter password to hash: ')
    
    # Generate the hash
    password_hash = generate_password_hash(
        password, 
        method=args.method,
        salt_length=args.salt_length
    )
    
    # Output
    if args.quiet:
        print(password_hash)
    else:
        print(f"\nGenerated Password Hash:")
        print("------------------------")
        print(f"{password_hash}")
        print("\nTo use in SQL:")
        print("-------------")
        sql = f"UPDATE rviuser SET password_hash = '{password_hash}' WHERE username = 'your_username';"
        print(sql)
        print("\nOr to insert a new user:")
        print("----------------------")
        sql_insert = f"""INSERT INTO rviuser (username, email, password_hash, role, created_at, needs_password_change, status) 
VALUES ('new_username', 'email@example.com', '{password_hash}', 'vetting_agent', NOW(), FALSE, 'active');"""
        print(sql_insert)
        print("\nNote: Be cautious with these SQL commands and ensure proper escaping of the hash in production environments.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)