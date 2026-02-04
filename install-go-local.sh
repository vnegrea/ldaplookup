#!/bin/bash
# Install Go locally for the current user

set -e

GO_VERSION="1.25.5"
GO_HOME="$HOME/myGo"
GO_TARBALL="/tmp/go${GO_VERSION}.linux-amd64.tar.gz"

echo "Downloading Go $GO_VERSION..."
wget -O "$GO_TARBALL" "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"

echo "Installing to $GO_HOME..."
mkdir -p "$GO_HOME/go-sdk" "$GO_HOME/go"
tar -xzf "$GO_TARBALL" -C "$GO_HOME/go-sdk" --strip-components=1
rm "$GO_TARBALL"

# Create env file with duplicate guard
echo 'export GOROOT="$HOME/myGo/go-sdk"' > "$GO_HOME/env.sh"
echo 'export GOPATH="$HOME/myGo/go"' >> "$GO_HOME/env.sh"
echo 'if [[ ":$PATH:" != *":$HOME/myGo/go-sdk/bin:"* ]]; then' >> "$GO_HOME/env.sh"
echo '    export PATH="$GOROOT/bin:$GOPATH/bin:$PATH"' >> "$GO_HOME/env.sh"
echo 'fi' >> "$GO_HOME/env.sh"

# Install garble using the new paths
export GOROOT="$GO_HOME/go-sdk"
export GOPATH="$GO_HOME/go"
export PATH="$GOROOT/bin:$GOPATH/bin:$PATH"
go install mvdan.cc/garble@latest

echo ""
echo "=== Installation complete ==="
go version
garble version
echo ""
echo "To use Go in this terminal:"
echo "  source ~/myGo/env.sh"
echo ""
echo "To make permanent, add to ~/.bashrc:"
echo "  source ~/myGo/env.sh"
echo ""
