#!/bin/bash

###############################################################################
# Polis Interactive Quickstart (Archived)
#
# Migrated from user-onbording/quickstart.sh. This script references assets
# (UI + sample agent) that are not included in the OSS core.
###############################################################################

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
print_header() {
    echo -e "\n${BLUE}════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}\n"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${YELLOW}ℹ $1${NC}"
}

# Check system requirements
check_requirements() {
    print_header "Checking System Requirements"

    local docker_available=false
    local go_available=false
    local kubectl_available=false

    # Check Docker
    if command -v docker &> /dev/null; then
        docker_version=$(docker --version)
        print_success "Docker found: $docker_version"
        docker_available=true
    else
        print_info "Docker not found (required for Option A)"
    fi

    # Check Go
    if command -v go &> /dev/null; then
        go_version=$(go version)
        print_success "Go found: $go_version"
        go_available=true
    else
        print_info "Go not found (required for Option B)"
    fi

    # Check kubectl
    if command -v kubectl &> /dev/null; then
        kubectl_version=$(kubectl version --client --short 2>/dev/null || echo "kubectl installed")
        print_success "kubectl found: $kubectl_version"
        kubectl_available=true
    else
        print_info "kubectl not found (required for Option C)"
    fi

    echo ""
    echo "Available options based on your system:"
    if [ "$docker_available" = true ]; then
        echo "  • Option A: Docker Compose (AVAILABLE) ✓"
    else
        echo "  • Option A: Docker Compose (not available)"
    fi

    if [ "$go_available" = true ]; then
        echo "  • Option B: Local Binary (AVAILABLE) ✓"
    else
        echo "  • Option B: Local Binary (not available)"
    fi

    if [ "$kubectl_available" = true ]; then
        echo "  • Option C: Kubernetes (AVAILABLE) ✓"
    else
        echo "  • Option C: Kubernetes (not available)"
    fi
    echo ""
}

check_requirements
print_info "This archived script is kept for reference. Use docs/onboarding/quickstart.md for the supported OSS quickstart."
