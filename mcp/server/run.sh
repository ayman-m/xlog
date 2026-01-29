#!/bin/bash

# XLog MCP Server startup script

set -e

echo "Starting XLog MCP Server..."

# Check if .env exists
if [ ! -f .env ]; then
    echo "Warning: .env file not found. Creating from .env.example..."
    if [ -f .env.example ]; then
        cp .env.example .env
        echo "Please edit .env with your configuration before running again."
        exit 1
    else
        echo "Error: .env.example not found!"
        exit 1
    fi
fi

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Virtual environment not found. Creating one..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Check if poetry is installed
if ! command -v poetry &> /dev/null; then
    echo "Poetry not found. Installing..."
    pip install poetry
fi

# Install dependencies
echo "Installing dependencies..."
poetry install

# Run the server
echo "Starting MCP server..."
python -m src.main

# Deactivate virtual environment on exit
deactivate
