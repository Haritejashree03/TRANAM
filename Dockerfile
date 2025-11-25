FROM python:3.11-slim

# Set app directory
WORKDIR /app

# Install system packages (needed by SQLAlchemy)
RUN apt-get update && apt-get install -y gcc

# Copy requirements first
COPY requirements.txt /app/

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy entire project
COPY . /app/

# Expose port used by Render
EXPOSE 8000

# Run gunicorn (Render sets PORT env)
CMD ["sh", "-c", "gunicorn app:app -b 0.0.0.0:$PORT"]
