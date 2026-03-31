# fail2ban-unban

A self-service web interface for unbanning IP addresses from fail2ban jails. This tool allows users to unban their own IP addresses without requiring admin access to the server.

## 🚀 Features

- **Self-service IP unbanning** - Users can unban themselves without admin intervention
- **Multi-jail support** - Unbans IP from all configured fail2ban jails simultaneously
- **Modern web interface** - Clean, responsive UI with IP detection helpers
- **Dockerized** - Easy deployment with Docker
- **Lightweight** - Based on Alpine Linux for minimal footprint
- **Reverse proxy ready** - Works behind nginx with custom subpaths
- **No authentication required** - Simple deployment for internal use (optional auth can be added)

## 📋 Prerequisites

- Docker and Docker Compose
- fail2ban running on the host system
- Access to `/var/run/fail2ban/fail2ban.sock` on the host

## 🏗️ Quick Start

### 1. Create project structure

```bash
mkdir fail2ban-unban
cd fail2ban-unban
mkdir templates
```

### 2. Create Dockerfile

```dockerfile
FROM alpine:3.19

WORKDIR /app

# Install system dependencies
RUN apk add --no-cache \
    python3 \
    py3-pip \
    py3-virtualenv \
    fail2ban \
    && ln -sf python3 /usr/bin/python \
    && ln -sf pip3 /usr/bin/pip

# Create virtual environment
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY app.py .
COPY templates/ ./templates/

# Create a non-root user
RUN adduser -D -u 1000 unbanuser && \
    chown -R unbanuser:unbanuser /app

# Expose port
EXPOSE 5000

# Run as root to access fail2ban socket
USER root

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--threads", "4", "app:app"]
```

### 3. Create requirements.txt

```txt
flask==3.0.0
gunicorn==21.2.0
python-dotenv==1.0.0
```

### 4. Create docker-compose.yml

```yaml
version: '3.8'

services:
  unban-me:
    build: .
    container_name: fail2ban-unban
    restart: unless-stopped
    user: root
    environment:
      - ALLOWED_JAILS=${ALLOWED_JAILS:-sshd}
    volumes:
      - /var/run/fail2ban:/var/run/fail2ban:ro
    ports:
      - "5000:5000"
    networks:
      - internal
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

networks:
  internal:
    driver: bridge
```

### 5. Create .env file

```bash
# Comma-separated list of fail2ban jails to unban IPs from
ALLOWED_JAILS=sshd,nginx-http-auth,postfix
```

### 6. Build and run

```bash
docker-compose up -d
```

### 7. Access the interface

```
http://localhost:5000
```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `ALLOWED_JAILS` | Comma-separated list of fail2ban jails | `sshd` | Yes |

### Available Jails

To see your available fail2ban jails:

```bash
sudo fail2ban-client status
```

Example output:
```
Status
|- Number of jail:	5
`- Jail list:	sshd, nginx-http-auth, postfix, courierauth, recidive
```

## 🌐 Nginx Reverse Proxy Configuration

To hide the tool behind a non-obvious path:

```nginx
# Replace 'banana' with your chosen path
location /banana/ {
    proxy_pass http://fail2ban-unban:5000/;
    proxy_http_version 1.1;
    
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Prefix /banana;
    
    proxy_connect_timeout 10s;
    proxy_send_timeout 30s;
    proxy_read_timeout 30s;
    proxy_buffering off;
    
    proxy_redirect http://fail2ban-unban:5000/ /banana/;
    proxy_redirect https://fail2ban-unban:5000/ /banana/;
}

location = /banana {
    return 301 /banana/;
}
```

### With Additional Security

```nginx
# Add basic authentication
location /banana/ {
    auth_basic "Restricted Access";
    auth_basic_user_file /etc/nginx/.htpasswd;
    
    # Rate limiting
    limit_req zone=unban burst=3 nodelay;
    
    # IP restrictions
    allow 192.168.1.0/24;
    allow 10.0.0.0/8;
    deny all;
    
    proxy_pass http://fail2ban-unban:5000/;
    # ... rest of config
}
```

## 🛡️ Security Considerations

1. **No built-in authentication** - Consider adding basic auth in nginx for production
2. **Rate limiting** - Prevent abuse by adding rate limits
3. **IP restrictions** - Restrict access to internal networks if possible
4. **Hidden paths** - Use non-obvious paths like `/banana` instead of `/unban`
5. **Logging** - All unban attempts are logged in the container and fail2ban

## 📊 Testing

### Health Check

```bash
curl http://localhost:5000/health
```

Expected response:
```json
{
  "status": "healthy",
  "fail2ban": "healthy",
  "jails_configured": 3,
  "base_path": ""
}
```

### Test Unban Endpoint

```bash
curl -X POST http://localhost:5000/unban \
  -H "Content-Type: application/json" \
  -d '{"ip":"1.2.3.4"}'
```

### View Jails

```bash
curl http://localhost:5000/jails
```

## 🐛 Troubleshooting

### Socket Permission Denied

If you see permission errors:

```bash
# Check socket permissions on host
ls -la /var/run/fail2ban/fail2ban.sock

# Ensure container runs as root (default in our config)
# The container runs as root in docker-compose.yml with: user: root
```

### Cannot Connect to fail2ban

```bash
# Verify fail2ban is running on host
sudo systemctl status fail2ban

# Test socket from container
docker exec fail2ban-unban fail2ban-client status
```

### View Container Logs

```bash
docker-compose logs -f
```

### Rebuild Container

```bash
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

## 📁 Project Structure

```
fail2ban-unban/
├── Dockerfile
├── docker-compose.yml
├── .env
├── requirements.txt
├── app.py
└── templates/
    └── index.html
```

## 🔍 How It Works

1. User accesses the web interface and enters their IP address
2. The Flask application validates the IP format
3. For each jail in `ALLOWED_JAILS`, the app runs:
   ```bash
   fail2ban-client set <jail> unbanip <ip>
   ```
4. Results are collected and displayed to the user
5. All actions are logged for audit purposes

## 📝 License

MIT License - See LICENSE file for details

## 👥 Contributing

Contributions are welcome! Please submit pull requests or open issues for bugs and feature requests.

## 🙏 Credits

Provided by **eXo ITOP Team** | [www.exoplatform.com](https://www.exoplatform.com)

## 📞 Support

For issues:
1. Check the troubleshooting section
2. Review container logs: `docker-compose logs`
3. Open an issue on GitHub

## 🗑️ Uninstallation

```bash
docker-compose down
docker rmi fail2ban-unban
rm -rf fail2ban-unban
```