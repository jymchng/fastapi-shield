FROM python:3.10-slim

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy the distribution files and example
COPY dist/ ./dist/
# COPY examples/demo.py ./

# Install the package from the distribution
RUN pip install dist/*.tar.gz

# # Make the demo script executable
# RUN chmod +x demo.py

# # Run the demo script
# CMD ["python", "demo.py"]
