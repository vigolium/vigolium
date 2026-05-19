#!/bin/bash

# Benchmark App Build Script
# Builds the benchmark application with multiple bundlers

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== Benchmark App Build Script ===${NC}"
echo ""

# Check if node_modules exists
if [ ! -d "node_modules" ]; then
    echo -e "${YELLOW}Installing dependencies...${NC}"
    npm install --legacy-peer-deps
fi

# Create dist directories
mkdir -p dist/{webpack5,webpack4,rollup,esbuild,parcel,vite}

# Build functions
build_webpack5() {
    echo -e "${YELLOW}Building with Webpack 5...${NC}"
    npx webpack --config configs/webpack5.config.js
    if [ -f "dist/webpack5/bundle.js" ]; then
        echo -e "${GREEN}✓ Webpack 5 build complete${NC}"
        ls -lh dist/webpack5/bundle.js
    else
        echo -e "${RED}✗ Webpack 5 build failed${NC}"
        return 1
    fi
}

build_rollup() {
    echo -e "${YELLOW}Building with Rollup...${NC}"
    npx rollup -c configs/rollup.config.mjs
    if [ -f "dist/rollup/bundle.js" ]; then
        echo -e "${GREEN}✓ Rollup build complete${NC}"
        ls -lh dist/rollup/bundle.js
    else
        echo -e "${RED}✗ Rollup build failed${NC}"
        return 1
    fi
}

build_esbuild() {
    echo -e "${YELLOW}Building with esbuild...${NC}"
    node configs/esbuild.config.js
    if [ -f "dist/esbuild/bundle.js" ]; then
        echo -e "${GREEN}✓ esbuild build complete${NC}"
        ls -lh dist/esbuild/bundle.js
    else
        echo -e "${RED}✗ esbuild build failed${NC}"
        return 1
    fi
}

build_vite() {
    echo -e "${YELLOW}Building with Vite...${NC}"
    npx vite build --config configs/vite.config.ts
    if [ -f "dist/vite/bundle.js" ]; then
        echo -e "${GREEN}✓ Vite build complete${NC}"
        ls -lh dist/vite/bundle.js
    else
        echo -e "${RED}✗ Vite build failed${NC}"
        return 1
    fi
}

# Main build
case "${1:-all}" in
    webpack5)
        build_webpack5
        ;;
    rollup)
        build_rollup
        ;;
    esbuild)
        build_esbuild
        ;;
    vite)
        build_vite
        ;;
    all)
        echo "Building all bundlers..."
        echo ""
        build_webpack5
        echo ""
        build_rollup
        echo ""
        build_esbuild
        echo ""
        build_vite
        echo ""
        echo -e "${GREEN}=== All builds complete ===${NC}"
        echo ""
        echo "Output files:"
        ls -lh dist/*/bundle.js 2>/dev/null || echo "Some builds may have failed"
        ;;
    docker)
        echo "Building with Docker..."
        docker-compose -f docker/docker-compose.yml build
        docker-compose -f docker/docker-compose.yml up
        ;;
    *)
        echo "Usage: $0 [webpack5|rollup|esbuild|vite|all|docker]"
        exit 1
        ;;
esac
