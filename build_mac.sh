#!/bin/bash
# ==========================================
# build_mac.sh - macOS Build (Run on actual Mac)
# ==========================================

echo "Building Go SNMP Tool Kit for macOS..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Install/update Fyne tools
echo -e "${YELLOW}Updating Fyne tools...${NC}"
go install fyne.io/tools/cmd/fyne@latest

# Add Go bin to PATH if not already there
export PATH=$PATH:$(go env GOPATH)/bin

# Clean previous builds
echo -e "${YELLOW}Cleaning previous builds...${NC}"
rm -f cmd/snmptk/snmptk cmd/snmptk/snmptk.exe

# Create dist directory
mkdir -p dist

# Build macOS version
echo -e "${YELLOW}Building macOS version...${NC}"
fyne package --target darwin --src ./cmd/snmptk

if [ -f cmd/snmptk/snmptk ]; then
    mv cmd/snmptk/snmptk dist/snmptk-mac
    chmod +x dist/snmptk-mac
    size=$(du -h dist/snmptk-mac | cut -f1)
    echo -e "${GREEN}SUCCESS: macOS build ($size)${NC}"
    
    # Test the build
    echo -e "${YELLOW}Testing macOS build...${NC}"
    if ./dist/snmptk-mac --help > /dev/null 2>&1 || [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ macOS executable runs successfully${NC}"
    else
        echo -e "${YELLOW}Note: GUI apps may not show help text${NC}"
    fi
    
    # Create app bundle (optional)
    echo -e "${YELLOW}Creating app bundle...${NC}"
    fyne package -os darwin -o dist/snmptk-mac.app ./cmd/snmptk
    if [ -d dist/snmptk-mac.app ]; then
        echo -e "${GREEN}✓ App bundle created: dist/snmptk-mac.app${NC}"
    fi
    
else
    echo -e "${RED}FAILED: macOS build${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}macOS build complete!${NC}"
echo -e "${CYAN}Run: ./dist/snmptk-mac${NC}"
echo -e "${CYAN}Or: open dist/snmptk-mac.app${NC}"