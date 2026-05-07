FROM alpine:3.19

WORKDIR /app

# Install system dependencies
RUN apk add --no-cache \
    python3 \
    py3-pip \
    py3-virtualenv \
    fail2ban \
    curl \
    && ln -sf python3 /usr/bin/python \
    && ln -sf pip3 /usr/bin/pip

# Create virtual environment
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements and install Python dependencies in virtual environment
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY app.py .
COPY templates/ ./templates/

# Create a non-root user and log directory
RUN adduser -D -u 1000 unbanuser && \
    chown -R unbanuser:unbanuser /app && \
    mkdir -p /var/log/fail2ban-unban && \
    chown unbanuser:unbanuser /var/log/fail2ban-unban

# Persist logs across restarts
VOLUME ["/var/log/fail2ban-unban"]

# Expose port
EXPOSE 5000

# Run as root to access fail2ban socket (entrypoint drops to unbanuser)
USER root

# Use gunicorn from virtual environment
CMD ["gunicorn", \
     "--bind", "0.0.0.0:5000", \
     "--workers", "2", \
     "--threads", "4", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "--log-level", "warning", \
     "app:app"]
