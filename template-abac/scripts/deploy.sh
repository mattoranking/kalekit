#!/bin/bash

# Manual deployment script (backup for CI/CD)

set -e

ENVIRONMENT=${1:-staging}

echo "🚀 Deploying to $ENVIRONMENT..."

# Pull latest code
echo "📥 Pulling latest code..."
git pull origin $(git branch --show-current)

# Build and deploy
echo "🏗️  Building and deploying containers..."
if [ "$ENVIRONMENT" == "production" ]; then
    echo "❌ Production deployments are handled via CI/CD (tag push or workflow_dispatch)."
    echo "   Backend deploys to DigitalOcean."
    echo "   Use: git tag v1.x.x && git push origin v1.x.x"
    exit 1
else
    docker-compose -f docker-compose.staging.yml build
    docker-compose -f docker-compose.staging.yml up -d --force-recreate
fi

# Clean up
echo "🧹 Cleaning up old images..."
docker system prune -af

# Show status
echo "📊 Container status:"
docker-compose -f docker-compose.staging.yml ps

echo "✅ Deployment complete!"
