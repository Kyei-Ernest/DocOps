#!/usr/bin/env bash

# Exit immediately if any command fails (except checked conditions)
set -e

# Terminal Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}===============================================${NC}"
echo -e "${BLUE}           DocOps Developer Setup              ${NC}"
echo -e "${BLUE}===============================================${NC}"
echo

# ── 1. Check Go Version ───────────────────────────────────────
echo -e "* Checking Go toolchain..."
if ! command -v go &> /dev/null; then
    echo -e "${RED}Error: Go is not installed. Please install Go 1.25+ before proceeding.${NC}"
    exit 1
fi

GO_VERSION_FULL=$(go version | awk '{print $3}')
GO_VERSION=${GO_VERSION_FULL#go}
echo -e "  - Found Go version: ${GREEN}${GO_VERSION_FULL}${NC}"

# Simple semantic check: extract major.minor
IFS='.' read -r -a VERSION_PARTS <<< "$GO_VERSION"
MAJOR=${VERSION_PARTS[0]}
MINOR=${VERSION_PARTS[1]}

if [ "$MAJOR" -lt 1 ] || { [ "$MAJOR" -eq 1 ] && [ "$MINOR" -lt 25 ]; }; then
    echo -e "${YELLOW}Warning: Go 1.25+ is recommended (found $GO_VERSION). If the build fails, please upgrade Go.${NC}"
else
    echo -e "  - Go version is compatible. ${GREEN}✔${NC}"
fi
echo

# ── 2. Check CGO Prerequisites ──────────────────────────────
echo -e "* Checking C compiler for CGO (SQLite dependency)..."
CGO_OK=false
if command -v gcc &> /dev/null; then
    echo -e "  - Found gcc: ${GREEN}$(gcc --version | head -n 1)${NC} ✔"
    CGO_OK=true
elif command -v clang &> /dev/null; then
    echo -e "  - Found clang: ${GREEN}$(clang --version | head -n 1)${NC} ✔"
    CGO_OK=true
fi

if [ "$CGO_OK" = false ]; then
    echo -e "${YELLOW}Warning: Neither gcc nor clang was found in your PATH.${NC}"
    echo -e "${YELLOW}SQLite requires CGO enabled to build, which requires a C compiler.${NC}"
    echo -e "${YELLOW}Please install gcc or clang using your system's package manager.${NC}"
else
    echo -e "  - C compiler is available. ${GREEN}✔${NC}"
fi
echo

# ── 3. Configure Environment (.env) ──────────────────────────
echo -e "* Checking environment configuration..."
if [ -f .env ]; then
    echo -e "  - .env file already exists. ${GREEN}✔${NC}"
else
    echo -e "  - .env file not found. Generating a secure one..."
    
    # Try generating a secure key. Fall back to standard options if urandom fails or behaves oddly
    SECURE_SECRET=$(tr -dc 'A-Za-z0-9' < /dev/urandom 2>/dev/null | head -c 32 || true)
    
    if [ -z "$SECURE_SECRET" ] && command -v openssl &> /dev/null; then
        SECURE_SECRET=$(openssl rand -hex 16)
    fi
    
    if [ -z "$SECURE_SECRET" ]; then
        # Last-resort fallback if no secure generators are accessible
        SECURE_SECRET="dev-insecure-secret-$(date +%s)"
    fi
    
    echo "JWT_SECRET=$SECURE_SECRET" > .env
    echo -e "  - Created .env file with a fresh, secure ${GREEN}JWT_SECRET${NC}. ${GREEN}✔${NC}"
fi
echo

# ── 4. Download Go dependencies ─────────────────────────────
echo -e "* Downloading Go dependencies..."
if go mod download; then
    echo -e "  - Dependencies downloaded successfully. ${GREEN}✔${NC}"
else
    echo -e "${RED}Error: Failed to download Go dependencies.${NC}"
    exit 1
fi
echo

echo -e "${GREEN}===============================================${NC}"
echo -e "${GREEN}       Setup Completed Successfully! 🎉         ${NC}"
echo -e "${GREEN}===============================================${NC}"
echo
echo -e "To start your DocOps server, run:"
echo -e "  ${BLUE}make run${NC}"
echo
echo -e "To run all unit tests, run:"
echo -e "  ${BLUE}make test${NC}"
echo
