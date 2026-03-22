#!/usr/bin/env bash
# scripts/bump-version.sh — bump PC Guard agent version in all VERSION files
# Usage: ./scripts/bump-version.sh 1.2.3

set -e

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
  echo "Usage: $0 <version>  (e.g. $0 1.2.3)"
  exit 1
fi

if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Error: version must be semver (e.g. 1.2.3)"
  exit 1
fi

echo "Bumping to $VERSION ..."

echo "$VERSION" > agent/VERSION
echo "✓ agent/VERSION"

echo "$VERSION" > agent-linux/VERSION
echo "✓ agent-linux/VERSION"

if [ -f web-app/package.json ]; then
  sed -i.bak "s/\"version\": \"[^\"]*\"/\"version\": \"$VERSION\"/" web-app/package.json
  rm -f web-app/package.json.bak
  echo "✓ web-app/package.json"
fi

echo ""
echo "Version bumped to $VERSION"
echo "Next: git commit -am \"chore: bump version to $VERSION\" && git push"
