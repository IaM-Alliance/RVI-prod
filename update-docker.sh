#!/bin/bash
# Script to update the Docker image with latest code changes and restart containers

set -e  # Exit immediately if a command exits with a non-zero status

# Define variables
IMAGE_NAME="iam-alliance-vetting"
TAG=$(date +"%Y%m%d-%H%M%S")
LATEST_TAG="latest"

# Show script information
echo "Updating Docker image for IaM-Alliance Vetting System"
echo "Image name: $IMAGE_NAME"
echo "New image tag: $TAG"

# Pull the latest code (if in a git repository)
if [ -d ".git" ]; then
    echo "Git repository detected. Pulling latest changes..."
    git pull
    echo "Git pull complete."
else 
    echo "Not a git repository. Skipping code update."
fi

# Build the Docker image with the current timestamp tag
echo "Building updated Docker image: $IMAGE_NAME:$TAG..."
docker build -t $IMAGE_NAME:$TAG .

# Also tag it as latest
echo "Tagging image as $IMAGE_NAME:$LATEST_TAG..."
docker tag $IMAGE_NAME:$TAG $IMAGE_NAME:$LATEST_TAG

# Stop and remove the existing containers
echo "Stopping existing containers..."
docker compose down

# Start the containers with the new image
echo "Starting containers with updated image..."
docker compose up -d

echo "Update complete. Application is now running with the latest changes."
echo "New image: $IMAGE_NAME:$TAG"