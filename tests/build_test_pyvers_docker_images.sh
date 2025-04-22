#!/bin/bash

# Create logs directory if it doesn't exist
mkdir -p ./tests/logs

# Clean up unused Docker objects
docker system prune -af

# Build Docker images in parallel with logging
docker build -t python-newtype-test-mul-vers:3.8 -f ./tests/Dockerfile-test-py3.8 . > ./tests/logs/py3.8-test.log 2>&1 &
docker build -t python-newtype-test-mul-vers:3.9 -f ./tests/Dockerfile-test-py3.9 . > ./tests/logs/py3.9-test.log 2>&1 &
docker build -t python-newtype-test-mul-vers:3.10 -f ./tests/Dockerfile-test-py3.10 . > ./tests/logs/py3.10-test.log 2>&1 &
docker build -t python-newtype-test-mul-vers:3.11 -f ./tests/Dockerfile-test-py3.11 . > ./tests/logs/py3.11-test.log 2>&1 &
docker build -t python-newtype-test-mul-vers:3.12 -f ./tests/Dockerfile-test-py3.12 . > ./tests/logs/py3.12-test.log 2>&1 &

# Wait for all background jobs to finish
wait

# Clean up unused Docker objects
docker system prune -af

echo "All Docker images built successfully."
