#!/usr/bin/env python3
"""
Database Export Script for IAM Alliance Application
This script exports the database to a SQL file for backup or migration.
"""

import os
import sys
import argparse
import subprocess
import datetime
from urllib.parse import urlparse
from dotenv import load_dotenv

def export_database(database_url, output_file=None, include_data=True, include_schema=True):
    """
    Export the PostgreSQL database to a SQL file.
    
    Args:
        database_url: PostgreSQL connection URL
        output_file: File to write the SQL to (default: based on database name)
        include_data: Whether to include table data
        include_schema: Whether to include schema (tables, functions, etc.)
    """
    if not output_file:
        now = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        parsed = urlparse(database_url)
        dbname = parsed.path[1:]  # Remove leading slash
        output_file = f"{dbname}_backup_{now}.sql"
    
    # Parse the database URL
    parsed = urlparse(database_url)
    dbname = parsed.path[1:]  # Remove leading slash
    user = parsed.username
    password = parsed.password
    host = parsed.hostname
    port = parsed.port or '5432'
    
    # Prepare pg_dump command
    cmd = ['pg_dump']
    
    # Add connection parameters
    cmd.extend(['-h', host, '-p', str(port), '-U', user])
    
    # Add output format (plain SQL)
    cmd.append('--format=p')
    
    # Determine what to include
    if include_schema and not include_data:
        cmd.append('--schema-only')
    elif include_data and not include_schema:
        cmd.append('--data-only')
    
    # Add database name
    cmd.append(dbname)
    
    # Set PGPASSWORD environment variable for password
    env = os.environ.copy()
    env['PGPASSWORD'] = password
    
    # Execute pg_dump and save to file
    try:
        print(f"Exporting database {dbname} to {output_file}...")
        with open(output_file, 'w') as f:
            subprocess.run(cmd, stdout=f, env=env, check=True)
        print(f"Database export completed successfully.")
        print(f"Output file: {os.path.abspath(output_file)}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error exporting database: {str(e)}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"Unexpected error: {str(e)}", file=sys.stderr)
        return False

def main():
    parser = argparse.ArgumentParser(description='Export IAM Alliance database to SQL')
    
    parser.add_argument('--env-file', default='.env',
                        help='Path to the .env file with DATABASE_URL')
    parser.add_argument('--output-file',
                        help='File to write the SQL to (default: based on database name)')
    parser.add_argument('--data-only', action='store_true',
                        help='Export only table data, not schema')
    parser.add_argument('--schema-only', action='store_true',
                        help='Export only schema, not table data')
    parser.add_argument('--database-url',
                        help='PostgreSQL connection URL (overrides .env file)')
    
    args = parser.parse_args()
    
    # Determine what to include based on flags
    include_schema = not args.data_only
    include_data = not args.schema_only
    
    # If both --data-only and --schema-only are specified, it's an error
    if args.data_only and args.schema_only:
        print("Error: Cannot specify both --data-only and --schema-only", file=sys.stderr)
        sys.exit(1)
    
    # Get database URL from args or .env file
    database_url = args.database_url
    if not database_url:
        # Load environment variables from .env file
        if os.path.exists(args.env_file):
            load_dotenv(args.env_file)
        
        database_url = os.environ.get('DATABASE_URL')
    
    if not database_url:
        print("Error: DATABASE_URL not provided and not found in .env file", file=sys.stderr)
        sys.exit(1)
    
    # Export the database
    if export_database(database_url, args.output_file, include_data, include_schema):
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()