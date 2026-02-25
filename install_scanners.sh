#!/bin/bash
# Install external security scanners for InfraScan

set -e

echo "Installing security scanners..."

# Install Checkov (Python package - should already be in requirements.txt)
echo "Checkov will be installed via pip requirements.txt"

# Check if Docker is installed
echo "Checking Docker installation..."
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first:"
    echo "   https://docs.docker.com/engine/install/"
    exit 1
else
    echo "✓ Docker is installed ($(docker --version))"
fi

# Install Docker Scout CLI
echo "Installing Docker Scout CLI..."
if docker-scout version &> /dev/null; then
    echo "✓ Docker Scout is already installed ($(docker-scout version 2>&1 | head -n1))"
else
    # Install to ~/.local/bin (no sudo required)
    mkdir -p ~/.local/bin
    curl -sSfL https://raw.githubusercontent.com/docker/scout-cli/main/install.sh | sh -s -- -b ~/.local/bin
    
    # Add to PATH if not already there
    if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
        # Check if already in bashrc
        if ! grep -q 'export PATH="$HOME/.local/bin:$PATH"' ~/.bashrc 2>/dev/null; then
            echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
            echo "✓ Added ~/.local/bin to PATH in ~/.bashrc"
        fi
        
        # Add to current session
        export PATH="$HOME/.local/bin:$PATH"
        echo "✓ Added ~/.local/bin to current PATH"
    fi
    
    echo "✓ Docker Scout installed successfully to ~/.local/bin/docker-scout"
fi

# Install Grype (alternative container scanner)
echo "Installing Grype CLI..."
if grype version &> /dev/null; then
    echo "✓ Grype is already installed ($(grype version 2>&1 | head -n1))"
else
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b ~/.local/bin
    echo "✓ Grype installed successfully to ~/.local/bin/grype"
fi

echo ""
echo "Scanner installation complete!"
echo ""
echo "⚠️  Restart your terminal session or run:"
echo "    source ~/.bashrc"
echo ""
echo "Verify installations:"
echo "  - Checkov: pip list | grep checkov"
echo "  - Docker Scout: docker-scout version"
echo "  - Grype: grype version"
echo "  - Docker: docker --version"
echo ""
echo "Configure container scanner in .env:"
echo "  CONTAINER_SCANNER=docker-scout  (default)"
echo "  CONTAINER_SCANNER=grype         (alternative)"
