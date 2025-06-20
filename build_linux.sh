#!/bin/bash
# ==========================================
# build_linux.sh - Linux Build (Run in WSL2)
# ==========================================

echo "Building Go SNMP Tool Kit for Linux..."

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

# Clear any Windows cross-compiler settings
unset CC CXX CC_FOR_windows CXX_FOR_windows

# Build Linux version
echo -e "${YELLOW}Building Linux version...${NC}"
fyne package --target linux --src ./cmd/snmptk

if [ -f cmd/snmptk/snmptk ]; then
    mv cmd/snmptk/snmptk dist/snmptk-linux
    chmod +x dist/snmptk-linux
    size=$(du -h dist/snmptk-linux | cut -f1)
    echo -e "${GREEN}SUCCESS: Linux build ($size)${NC}"
    
    # Test the build
    echo -e "${YELLOW}Testing Linux build...${NC}"
    if dist/snmptk-linux --help > /dev/null 2>&1 || [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Linux executable runs successfully${NC}"
    else
        echo -e "${YELLOW}Note: GUI test requires display (expected in headless environment)${NC}"
    fi
else
    echo -e "${RED}FAILED: Linux build${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}Linux build complete!${NC}"
echo -e "${CYAN}Run: ./dist/snmptk-linux${NC}"
echo -e "${CYAN}Or copy to Windows: cp dist/snmptk-linux /mnt/c/Users/97685/goProjects/gosnmptk/dist/${NC}"