#!/bin/bash

# Script to create a new release

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Get current version from git tags
CURRENT_VERSION=$(git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0")
CURRENT_VERSION=${CURRENT_VERSION#v}  # Remove 'v' prefix

echo -e "${BLUE}Current version: v${CURRENT_VERSION}${NC}"
echo ""

# Parse version
IFS='.' read -r MAJOR MINOR PATCH <<< "$CURRENT_VERSION"

echo "Select release type:"
echo "1) Major (breaking changes) - v$((MAJOR+1)).0.0"
echo "2) Minor (new features) - v${MAJOR}.$((MINOR+1)).0"
echo "3) Patch (bug fixes) - v${MAJOR}.${MINOR}.$((PATCH+1))"
echo "4) Custom version"
echo ""
read -p "Enter choice [1-4]: " choice

case $choice in
  1)
    NEW_VERSION="$((MAJOR+1)).0.0"
    TYPE="major"
    ;;
  2)
    NEW_VERSION="${MAJOR}.$((MINOR+1)).0"
    TYPE="minor"
    ;;
  3)
    NEW_VERSION="${MAJOR}.${MINOR}.$((PATCH+1))"
    TYPE="patch"
    ;;
  4)
    read -p "Enter version (X.Y.Z): " NEW_VERSION
    TYPE="custom"
    ;;
  *)
    echo -e "${RED}Invalid choice${NC}"
    exit 1
    ;;
esac

echo ""
echo -e "${BLUE}New version will be: v${NEW_VERSION}${NC}"
echo -e "${BLUE}Release type: ${TYPE}${NC}"
echo ""

# Confirm
read -p "Create release v${NEW_VERSION}? (y/n): " confirm
if [ "$confirm" != "y" ]; then
  echo "Cancelled"
  exit 0
fi

# Ensure we're on main and up to date
echo "Checking out main branch..."
git checkout main
git pull origin main

# Check if tag exists
if git rev-parse "v${NEW_VERSION}" >/dev/null 2>&1; then
  echo -e "${RED}Tag v${NEW_VERSION} already exists!${NC}"
  exit 1
fi

# Create tag
echo "Creating tag v${NEW_VERSION}..."
git tag -a "v${NEW_VERSION}" -m "Release v${NEW_VERSION}"

# Push tag
echo "Pushing tag to GitHub..."
git push origin "v${NEW_VERSION}"

echo ""
echo -e "${GREEN}✅ Release v${NEW_VERSION} created!${NC}"
echo ""
echo "📦 Tag pushed to GitHub"
echo "🚀 Production deployment will start automatically"
echo "🔗 Monitor at: https://github.com/$(git remote get-url origin | sed 's/.*github.com[:/]\(.*\)\.git/\1/')/actions"
echo ""
echo -e "${BLUE}To rollback if needed:${NC}"
echo "  git tag -d v${NEW_VERSION}"
echo "  git push origin :refs/tags/v${NEW_VERSION}"
