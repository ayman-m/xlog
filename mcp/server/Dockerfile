FROM python:3.12-slim

WORKDIR /app

# Copy dependency files
COPY requirements.txt ./

# Upgrade pip and install build dependencies
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code and resources
COPY src/ ./src/
COPY resources/ ./resources/

# Copy default skills to a staging location
# These will be copied to /app/skills on first run if volume is empty
COPY skills/ ./skills-default/

# Create empty skills directory for volume mount
RUN mkdir -p /app/skills

# Copy and set up entrypoint script
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV MCP_TRANSPORT=stdio
ENV PYTHONPATH=/app

# Run the entrypoint script
ENTRYPOINT ["/app/entrypoint.sh"]
