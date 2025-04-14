# Docker Setup for IaM-Alliance Vetting System

This document provides instructions for setting up, building, and deploying the IaM-Alliance Vetting System using Docker.

## Prerequisites

- Docker installed on your system
- Docker Compose installed on your system
- Git (optional, for version control)

## Quick Start

1. Clone or download the repository
2. Run the build script to create the Docker image:
   ```bash
   chmod +x build-docker.sh
   ./build-docker.sh
   ```
3. Start the application with Docker Compose:
   ```bash
   docker compose up -d
   ```
4. Access the application at http://localhost:5000

## Configuration

### Environment Variables

Create a `.env` file in the project root to configure the application:

```
# Database
POSTGRES_USER=postgres
POSTGRES_PASSWORD=your_secure_db_password
POSTGRES_DB=iam_alliance

# Security
SESSION_SECRET=your_secure_session_key

# Matrix API (if used)
MATRIX_ADMIN_TOKEN=your_matrix_token

# Email Configuration (if used)
SMTP_RELAY_SERVER=your_smtp_server
MAILJET_API_KEY=your_mailjet_key
MAILJET_SECRET_KEY=your_mailjet_secret
```

## Container Management

### Building the Image

```bash
./build-docker.sh
```

This creates a Docker image with a timestamp tag and the `latest` tag.

### Updating the Application

To update the application with the latest code changes:

```bash
./update-docker.sh
```

This script:
1. Pulls the latest code (if in a Git repository)
2. Rebuilds the Docker image
3. Restarts the containers with the new image

### Updating Packages

To update system and Python packages:

```bash
./update-packages.sh
```

This script:
1. Creates a new Docker image with updated packages
2. Restarts the containers with the updated image

## Production Deployment

To deploy to a production environment:

```bash
./deploy-docker.sh your-registry.com [username] [password]
```

This script:
1. Builds and tags the Docker image
2. Pushes the image to the specified registry
3. Creates a `docker-compose.prod.yml` file for production deployment

On your production server:
1. Copy the `docker-compose.prod.yml` file
2. Create a `.env` file with production values
3. Run: `docker compose -f docker-compose.prod.yml up -d`

## Persistent Data

- Database data is stored in a Docker volume named `postgres_data`
- Uploaded files are stored in the `uploads` directory, which is mounted as a volume

## Accessing Logs

To view logs from the containers:

```bash
# All containers
docker compose logs

# Specific container
docker compose logs web
docker compose logs db

# Follow logs
docker compose logs -f
```

## Troubleshooting

### Database Connection Issues

If the web application cannot connect to the database:

1. Check if the database container is running:
   ```bash
   docker compose ps
   ```

2. Check database logs:
   ```bash
   docker compose logs db
   ```

3. Verify environment variables in the `.env` file

### Application Errors

1. Check application logs:
   ```bash
   docker compose logs web
   ```

2. Access a shell in the web container for debugging:
   ```bash
   docker compose exec web bash
   ```

## Cleanup

To stop and remove containers:

```bash
docker compose down
```

To stop containers, remove volumes, and remove images:

```bash
docker compose down -v --rmi all
```