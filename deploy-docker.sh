#!/bin/bash
# Script to deploy the Docker image to a production environment

set -e  # Exit immediately if a command exits with a non-zero status

# Check if correct number of arguments provided
if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <registry_url> [username] [password]"
    echo "  registry_url: The URL of the Docker registry (e.g., registry.example.com)"
    echo "  username: (Optional) Username for registry authentication"
    echo "  password: (Optional) Password for registry authentication"
    exit 1
fi

# Define variables
REGISTRY_URL="$1"
IMAGE_NAME="iam-alliance-vetting"
TAG=$(date +"%Y%m%d-%H%M%S")
LATEST_TAG="latest"
FULL_IMAGE_NAME="$REGISTRY_URL/$IMAGE_NAME"

# Show script information
echo "Deploying Docker image for IaM-Alliance Vetting System to $REGISTRY_URL"
echo "Image name: $FULL_IMAGE_NAME"
echo "Image tag: $TAG"

# Login to registry if credentials provided
if [ "$#" -ge 3 ]; then
    USERNAME="$2"
    PASSWORD="$3"
    
    echo "Logging in to registry $REGISTRY_URL..."
    echo "$PASSWORD" | docker login "$REGISTRY_URL" -u "$USERNAME" --password-stdin
    echo "Login successful."
else
    echo "No credentials provided. Assuming you're already logged in to the registry."
fi

# Build the Docker image
echo "Building Docker image: $FULL_IMAGE_NAME:$TAG..."
docker build -t "$FULL_IMAGE_NAME:$TAG" .

# Tag it as latest
echo "Tagging image as $FULL_IMAGE_NAME:$LATEST_TAG..."
docker tag "$FULL_IMAGE_NAME:$TAG" "$FULL_IMAGE_NAME:$LATEST_TAG"

# Push the images to the registry
echo "Pushing image $FULL_IMAGE_NAME:$TAG to registry..."
docker push "$FULL_IMAGE_NAME:$TAG"

echo "Pushing image $FULL_IMAGE_NAME:$LATEST_TAG to registry..."
docker push "$FULL_IMAGE_NAME:$LATEST_TAG"

echo "Deployment complete."
echo "Images pushed to registry:"
echo "  $FULL_IMAGE_NAME:$TAG"
echo "  $FULL_IMAGE_NAME:$LATEST_TAG"

# Create a production docker-compose.yml file
cat > docker-compose.prod.yml << EOL
version: '3.8'

services:
  db:
    image: postgres:15-alpine
    volumes:
      - postgres_data:/var/lib/postgresql/data/
    environment:
      - POSTGRES_USER=\${POSTGRES_USER:-postgres}
      - POSTGRES_PASSWORD=\${POSTGRES_PASSWORD:-postgres}
      - POSTGRES_DB=\${POSTGRES_DB:-iam_alliance}
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 5s
      timeout: 5s
      retries: 5
    restart: always
    networks:
      - app-network

  web:
    image: ${FULL_IMAGE_NAME}:${LATEST_TAG}
    command: gunicorn --bind 0.0.0.0:5000 --workers 3 main:app
    volumes:
      - ./uploads:/app/uploads
    ports:
      - "5000:5000"
    environment:
      - DATABASE_URL=postgresql://\${POSTGRES_USER:-postgres}:\${POSTGRES_PASSWORD:-postgres}@db:5432/\${POSTGRES_DB:-iam_alliance}
      - SESSION_SECRET=\${SESSION_SECRET}
      - MATRIX_ADMIN_TOKEN=\${MATRIX_ADMIN_TOKEN}
      - SMTP_RELAY_SERVER=\${SMTP_RELAY_SERVER}
      - SMTP_RELAY_AUTHPW=\${SMTP_RELAY_AUTHPW}
#      - MAILJET_API_KEY=\${MAILJET_API_KEY}
#      - MAILJET_SECRET_KEY=\${MAILJET_SECRET_KEY}
    depends_on:
      db:
        condition: service_healthy
    restart: always
    networks:
      - app-network

volumes:
  postgres_data:

networks:
  app-network:
    driver: bridge
EOL

echo "Created production docker-compose.prod.yml file."
echo "To deploy on your production server:"
echo "1. Copy the docker-compose.prod.yml to your server"
echo "2. Create a .env file with your environment variables"
echo "3. Run: docker compose -f docker-compose.prod.yml up -d"
