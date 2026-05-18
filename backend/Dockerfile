FROM python:3.12-slim

WORKDIR /app

# Prevent Python from writing pyc files to disc
ENV PYTHONDONTWRITEBYTECODE=1
# Prevent Python from buffering stdout and stderr
ENV PYTHONUNBUFFERED=1

# Copy required files for installation
COPY pyproject.toml README.md ./
COPY backend/ ./backend/
COPY cli/ ./cli/

# Install dependencies (using --no-cache-dir to reduce image size)
RUN pip install --no-cache-dir .

# Create data directory for SQLite persistence
RUN mkdir -p /app/data

EXPOSE 8000

# Default command (used in prod, overridden in dev)
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
