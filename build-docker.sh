#!/bin/bash
# Script to build the Docker image for the IaM-Alliance Vetting System

set -e  # Exit immediately if a command exits with a non-zero status

# Define variables
IMAGE_NAME="iam-alliance-vetting"
TAG=$(date +"%Y%m%d-%H%M%S")
LATEST_TAG="latest"

# Show script information
echo "Building Docker image for IaM-Alliance Vetting System"
echo "Image name: $IMAGE_NAME"
echo "Image tag: $TAG"

# Build the Docker image with the current timestamp tag
echo "Building Docker image: $IMAGE_NAME:$TAG..."
docker build -t $IMAGE_NAME:$TAG .

# Also tag it as latest
echo "Tagging image as $IMAGE_NAME:$LATEST_TAG..."
docker tag $IMAGE_NAME:$TAG $IMAGE_NAME:$LATEST_TAG

echo "Image build complete."
echo "To run the application with Docker Compose, use:"
echo "   docker compose up -d"
echo ""
echo "To push the image to a repository, use:"
echo "   docker push $IMAGE_NAME:$TAG"
echo "   docker push $IMAGE_NAME:$LATEST_TAG"
