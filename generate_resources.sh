#!/bin/bash
# Fixed resource generation script for Go SNMP Tool Kit

set -e

echo "🔧 Generating resources for Go SNMP Tool Kit (Fixed)..."

# Check if fyne command is available
if ! command -v fyne &> /dev/null; then
    echo "📦 Installing fyne tools..."
    go install fyne.io/tools/cmd/fyne@latest
    
    # Add GOPATH/bin to PATH if not already there
    export PATH=$PATH:$(go env GOPATH)/bin
    
    if ! command -v fyne &> /dev/null; then
        echo "❌ Error: Failed to install fyne tools"
        echo "Make sure $(go env GOPATH)/bin is in your PATH"
        exit 1
    fi
fi

# Create internal/resources directory
echo "📁 Creating resources directory..."
mkdir -p internal/resources

# Generate SVG logo resource with correct package
if [ -f "assets/logo.svg" ]; then
    echo "🎨 Generating SVG logo resource..."
    fyne bundle -package resources -o internal/resources/logo.go assets/logo.svg
    echo "✅ SVG logo resource generated: internal/resources/logo.go"
else
    echo "❌ Error: assets/logo.svg not found"
    echo "Please ensure the logo.svg file is in the assets/ directory"
    exit 1
fi

# Generate app icon resource from existing Icon.png if present
if [ -f "cmd/snmptk/Icon.png" ]; then
    echo "🖼️  Generating app icon resource..."
    fyne bundle -package resources -o internal/resources/icon.go cmd/snmptk/Icon.png
    echo "✅ App icon resource generated: internal/resources/icon.go"
fi

echo ""
echo "🎉 Resource generation complete!"
echo ""
echo "Generated resources:"
echo "  - internal/resources/logo.go (SVG logo)"
if [ -f "internal/resources/icon.go" ]; then
    echo "  - internal/resources/icon.go (App icon)"
fi
echo ""
echo "📝 Resources are now properly packaged and ready to import!"