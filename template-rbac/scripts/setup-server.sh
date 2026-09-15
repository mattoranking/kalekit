#!/bin/bash

# Setup script for DigitalOcean droplet — kalekit

set -e

echo "Setting up kalekit on DigitalOcean..."

# Update system
echo "Updating system packages..."
sudo apt-get update
sudo apt-get upgrade -y

# Install Docker
echo "Installing Docker..."
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
rm get-docker.sh

# Install Docker Compose
echo "Installing Docker Compose..."
sudo apt-get install docker-compose-plugin -y

# Create deploy user
echo "Creating deploy user..."
sudo adduser --disabled-password --gecos "" deploy || true
sudo usermod -aG sudo deploy
sudo usermod -aG docker deploy

# Setup deployment directories
echo "Creating deployment directories..."
sudo mkdir -p /home/deploy/opt/kalekit/{staging,preview,production,traefik}
sudo chown -R deploy:deploy /home/deploy/opt/kalekit

# Create shared Traefik network
echo "Creating shared Traefik network..."
docker network create traefik-public 2>/dev/null || true

# Setup SSH for deploy user
echo "Setting up SSH for deploy user..."
sudo -u deploy mkdir -p /home/deploy/.ssh
sudo -u deploy touch /home/deploy/.ssh/authorized_keys
sudo chmod 700 /home/deploy/.ssh
sudo chmod 600 /home/deploy/.ssh/authorized_keys

# Basic firewall setup (only allow SSH, HTTP, HTTPS)
echo "Configuring firewall..."
sudo apt-get install ufw -y
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw --force enable

# Disable password-based SSH login
echo "Hardening SSH..."
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
# validate before applying, and cover both unit names (ssh on Debian/Ubuntu, sshd on RHEL)
sudo sshd -t
sudo systemctl reload ssh 2>/dev/null || sudo systemctl reload sshd 2>/dev/null \
  || sudo systemctl restart ssh 2>/dev/null || sudo systemctl restart sshd

# Certbot renewal hook — restarts Traefik after cert renewal
echo "Installing certbot renewal hook..."
sudo mkdir -p /etc/letsencrypt/renewal-hooks/deploy
sudo tee /etc/letsencrypt/renewal-hooks/deploy/restart-traefik.sh > /dev/null <<'HOOK'
#!/bin/bash
docker restart kalekit_traefik 2>/dev/null || true
HOOK
sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/restart-traefik.sh

# Make cert directories readable so the deploy user can list them
# (Traefik runs as root in the container and can read privkey files)
echo "Setting cert directory permissions for deploy user..."
sudo chmod 755 /etc/letsencrypt/{live,archive} 2>/dev/null || true
sudo find /etc/letsencrypt/archive -type d -exec chmod 755 {} + 2>/dev/null || true

echo "
Next steps:
1. Add your SSH public key to /home/deploy/.ssh/authorized_keys
2. Set up GitHub Actions secrets (CR_PAT, STAGING_HOST, STAGING_USER, STAGING_SSH_KEY, etc.)
3. Push to main branch to trigger staging deployment
4. Traefik serves your existing certbot certs; certbot renewal auto-restarts Traefik
"

echo "Server setup complete!"
