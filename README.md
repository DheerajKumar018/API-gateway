# Installation Guide

## Prerequisites
- Python 3.8 or higher
- Nginx
- Git

## Installation Steps

### macOS

1. **Install Dependencies**
   ```bash
   # Install Homebrew if not installed
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

   # Install Python and Nginx
   brew install python3
   brew install nginx
   ```

2. **Set up Virtual Environment**
   ```bash
   # Create virtual environment
   python3 -m venv venv

   # Activate virtual environment
   source venv/bin/activate
   ```

3. **Install Python Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure Nginx**
   ```bash
   # Backup original nginx config
   sudo cp /opt/homebrew/etc/nginx/nginx.conf /opt/homebrew/etc/nginx/nginx.conf.backup

   # Copy new configuration
   sudo cp nginx_upt_1.conf /opt/homebrew/etc/nginx/nginx.conf

   # Set proper permissions
   sudo chown root:wheel /opt/homebrew/etc/nginx/nginx.conf
   sudo chmod 644 /opt/homebrew/etc/nginx/nginx.conf
   ```

### Linux

1. **Install Dependencies**
   ```bash
   # For Ubuntu/Debian
   sudo apt update
   sudo apt install python3 python3-venv nginx

   # For CentOS/RHEL
   sudo yum install python3 nginx
   ```

2. **Set up Virtual Environment**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install Python Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure Nginx**
   ```bash
   # Backup original nginx config
   sudo cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.backup

   # Copy new configuration
   sudo cp nginx_upt_1.conf /etc/nginx/nginx.conf

   # Set proper permissions
   sudo chown root:root /etc/nginx/nginx.conf
   sudo chmod 644 /etc/nginx/nginx.conf
   ```

### Windows

1. **Install Dependencies**
   - Download and install Python from [python.org](https://www.python.org/downloads/)
   - Download and install Nginx from [nginx.org](http://nginx.org/en/download.html)

2. **Set up Virtual Environment**
   ```cmd
   # Create virtual environment
   python -m venv venv

   # Activate virtual environment
   .\venv\Scripts\activate
   ```

3. **Install Python Dependencies**
   ```cmd
   pip install -r requirements.txt
   ```

4. **Configure Nginx**
   - Backup original nginx.conf
   - Copy nginx_upt_1.conf to nginx installation directory
   - Default location: `C:\nginx\conf\nginx.conf`

## Configuration

### Nginx Configuration
- The nginx configuration file (`nginx_upt_1.conf`) contains:
  - Rate limiting settings
  - Proxy settings for backend services
  - Error handling
  - Load balancing configuration

### Environment Variables
No environment variables are required by default. However, you can configure:
- `ADMIN_KEY` - For admin endpoints (default: "supersecretadminkey")
- Custom backend URLs in the `ROUTE_MAP` dictionary in `main.py`

## Running the Application

1. **Start Nginx**
   ```bash
   # macOS
   sudo nginx

   # Linux
   sudo systemctl start nginx

   # Windows
   start nginx
   ```

2. **Start the API Gateway**
   ```bash
   # Ensure virtual environment is activated
   python main.py
   ```

3. **Start Backend Services**
   ```bash
   # Start with different ports
   python backend.py 9000  # Default backend
   python backend.py 9100  # Auth service
   python backend.py 9200  # Users service
   python backend.py 9300  # Orders service
   ```

## Common Errors and Solutions

### macOS
1. **Nginx Permission Denied**
   ```bash
   Error: nginx: [emerg] open() "/opt/homebrew/var/run/nginx.pid" failed
   Solution: sudo chown -R user:staff /opt/homebrew/var/run/
   ```

2. **Port Already in Use**
   ```bash
   Error: nginx: [emerg] bind() to 0.0.0.0:80 failed (48: Address already in use)
   Solution: sudo lsof -i :80 && sudo kill -9 PID
   ```

### Linux
1. **SELinux Blocking Nginx**
   ```bash
   Error: nginx: [emerg] bind() to [::]:80 failed (13: Permission denied)
   Solution: sudo setsebool -P httpd_can_network_connect 1
   ```

2. **Missing Permissions**
   ```bash
   Error: nginx: [alert] could not open error log file
   Solution: sudo chmod -R 755 /var/log/nginx
   ```

### Windows
1. **Port Conflicts**
   ```
   Error: nginx: [emerg] bind() to 0.0.0.0:80 failed
   Solution: netstat -ano | findstr :80
           taskkill /PID [PID] /F
   ```

2. **Path Issues**
   ```
   Error: nginx: the configuration file "nginx.conf" syntax is ok
   nginx: [emerg] open() "logs/error.log" failed
   Solution: Create logs directory in nginx installation folder
   ```

## Health Check
- Test if the API gateway is running: `http://localhost:8000/health`
- Test if nginx is running: `http://localhost/health`

## Troubleshooting

1. **Nginx Configuration Test**
   ```bash
   # Test configuration
   sudo nginx -t

   # Reload configuration
   sudo nginx -s reload
   ```

2. **Check Logs**
   ```bash
   # Nginx error logs
   # macOS
   tail -f /opt/homebrew/var/log/nginx/error.log

   # Linux
   tail -f /var/log/nginx/error.log

   # Windows
   tail -f C:\nginx\logs\error.log
   ```

3. **Common Issues**
   - Rate limiting errors (HTTP 429)
   - Backend service unavailable (HTTP 502)
   - Permission denied for log files
   - Port conflicts with existing services