#!/bin/bash
# Script to update packages in the Docker image

set -e  # Exit immediately if a command exits with a non-zero status

# Define variables
IMAGE_NAME="iam-alliance-vetting"
TAG=$(date +"%Y%m%d-%H%M%S")-updated
LATEST_TAG="latest"

# Show script information
echo "Updating packages in Docker image for IaM-Alliance Vetting System"
echo "Image name: $IMAGE_NAME"
echo "New image tag: $TAG"

# Create a temporary Dockerfile for updating packages
cat > Dockerfile.update << EOL
FROM $IMAGE_NAME:latest

# Update system packages
RUN apt-get update && apt-get upgrade -y && apt-get clean && rm -rf /var/lib/apt/lists/*

# Update Python packages
RUN pip install --upgrade pip && \\
    pip install --no-cache-dir --upgrade -r requirements.txt
EOL

# Create a requirements.txt from pyproject.toml if it doesn't exist
if [ ! -f "requirements.txt" ]; then
    echo "Creating requirements.txt from pyproject.toml..."
    python -c "
import tomli
import sys

try:
    with open('pyproject.toml', 'rb') as f:
        data = tomli.load(f)
    
    if 'dependencies' in data.get('project', {}):
        deps = data['project']['dependencies']
        with open('requirements.txt', 'w') as req:
            for dep in deps:
                req.write(f'{dep}\n')
        print('requirements.txt created successfully')
    else:
        print('No dependencies found in pyproject.toml')
        sys.exit(1)
except Exception as e:
    print(f'Error creating requirements.txt: {e}')
    sys.exit(1)
"

    # If Python script failed, try pip freeze as fallback
    if [ $? -ne 0 ]; then
        echo "Failed to extract from pyproject.toml, using pip freeze as fallback..."
        pip freeze > requirements.txt
    fi
fi

# Build the updated Docker image
echo "Building updated Docker image: $IMAGE_NAME:$TAG..."
docker build -t $IMAGE_NAME:$TAG -f Dockerfile.update .

# Tag it as latest
echo "Tagging image as $IMAGE_NAME:$LATEST_TAG..."
docker tag $IMAGE_NAME:$TAG $IMAGE_NAME:$LATEST_TAG

# Clean up the temporary Dockerfile
rm Dockerfile.update

# Restart containers with the updated image
echo "Stopping existing containers..."
docker compose down

echo "Starting containers with updated image..."
docker compose up -d

echo "Package update complete. Application is now running with updated packages."
echo "New image: $IMAGE_NAME:$TAG"