# ─── Soteria Backend Dockerfile ───
# Python 3.11 slim image for a lean production container
FROM python:3.11-slim

# Set the working directory inside the container
WORKDIR /app

# Install system dependencies needed for ML and PDF libraries
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better layer caching
COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire project into the container
COPY . .

# Expose the default Flask port (overridable by $PORT for cloud platforms)
EXPOSE 5001

# Start the Flask app via gunicorn.
# $PORT is automatically set by cloud platforms (Render, Railway, Heroku).
# Falls back to 5001 for local Docker usage.
CMD gunicorn --bind 0.0.0.0:${PORT:-5001} --workers 1 --timeout 120 --preload middleware.app:app
