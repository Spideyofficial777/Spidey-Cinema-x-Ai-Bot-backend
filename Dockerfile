# Use Python 3.11 instead of 3.12
FROM python:3.11-slim
# Install system dependencies for building wheels
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    libffi-dev \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*
# Set working directory
WORKDIR /app
# Copy your app files
COPY . /app/
# Upgrade pip and install Python dependencies
RUN pip install --upgrade pip \
    && pip install -r requirements.txt
# Start your app (adjust if using uvicorn or another server)
CMD ["python", "server.py"]
