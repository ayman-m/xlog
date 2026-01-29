# Base image
FROM python:3.12

# Set the working directory
WORKDIR /

# Copy requirements.txt
COPY requirements.txt .

# Update and install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libssl-dev \
    python3-dev \
    git \
    wget \
    swig \  
    && pip install --no-cache-dir -r requirements.txt \
    && apt-get remove -y build-essential python3-dev git wget swig \ 
    && apt-get autoremove -y && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy the application code
COPY . .

# Set the command to run the application
CMD ["python", "main.py"]
