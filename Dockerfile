FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    FLASK_APP=main.py

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    git \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker cache
COPY pyproject.toml .
COPY uv.lock .

# Create and activate virtual environment
RUN python -m venv /opt/RVI-prod/venv
# Enable venv
ENV PATH="/opt/RVI-prod/venv/bin:$PATH"

# Install Python dependencies
RUN pip install --upgrade pip && \
    pip install uv && \
    uv pip install -e .

# Copy project files
COPY . .

# Create directories for uploads if they don't exist
RUN mkdir -p uploads/evidence

# Set correct permissions
RUN chmod -R 755 uploads

# Expose the port the app runs on
EXPOSE 5000

# Command to run the application with Gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "3", "main:app"]