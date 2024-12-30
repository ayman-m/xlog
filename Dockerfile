# Base Stage: Install Dependencies
FROM python:3.8-slim AS base

# Set the working directory in the container
WORKDIR /

# Copy the requirements.txt file into the container
COPY requirements.txt .

# Install the Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the bot script into the container
COPY . .

# Local Run Stage: Add CMD for Local Execution
FROM base AS local
CMD ["python", "main.py"]

# No CMD Stage
FROM base AS available
