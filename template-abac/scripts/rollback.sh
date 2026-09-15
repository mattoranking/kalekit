#!/bin/bash

# Rollback to previous version

set -e

echo "🔄 Production Rollback Script"
echo ""

# Get current version
CURRENT_VERSION=$(git describe --tags --abbrev=0 2>/dev/null || echo "none")
echo "Current production version: $CURRENT_VERSION"

# Get previous version
PREVIOUS_VERSION=$(git describe --tags --abbrev=0 HEAD~1 2>/dev/null || echo "none")

if [ "$PREVIOUS_VERSION" == "none" ]; then
  echo "❌ No previous version found"
  exit 1
fi

echo "Previous version: $PREVIOUS_VERSION"
echo ""
read -p "Rollback to $PREVIOUS_VERSION? (y/n): " confirm

if [ "$confirm" != "y" ]; then
  echo "Cancelled"
  exit 0
fi

echo "🚀 Triggering rollback to $PREVIOUS_VERSION..."

# Option 1: Create a new tag pointing to previous version
ROLLBACK_TAG="$PREVIOUS_VERSION-rollback-$(date +%s)"
git tag -a "$ROLLBACK_TAG" $PREVIOUS_VERSION -m "Rollback to $PREVIOUS_VERSION"
git push origin "$ROLLBACK_TAG"

echo ""
echo "✅ Rollback initiated"
echo "📦 New tag: $ROLLBACK_TAG"
echo "🔗 Monitor deployment at GitHub Actions"
