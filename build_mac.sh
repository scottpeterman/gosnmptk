#!/bin/bash
# ==========================================
# Enhanced macOS Build Script for Go SNMP Tool Kit
# ==========================================

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
GRAY='\033[0;37m'
NC='\033[0m' # No Color

# Default values
TARGET="all"
CLEAN=false
TEST=false
ARCH="amd64"
CREATE_BUNDLE=true

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--target)
            TARGET="$2"
            shift 2
            ;;
        -c|--clean)
            CLEAN=true
            shift
            ;;
        --test)
            TEST=true
            shift
            ;;
        -a|--arch)
            ARCH="$2"
            shift 2
            ;;
        --no-bundle)
            CREATE_BUNDLE=false
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  -t, --target TARGET   Build target (all, snmptk, scanner, scanner-ext, report)"
            echo "  -c, --clean          Clean previous builds"
            echo "  --test               Test builds after creation"
            echo "  -a, --arch ARCH      Architecture (amd64, arm64)"
            echo "  --no-bundle          Skip creating .app bundles"
            echo "  -h, --help           Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}Go SNMP Tool Kit - macOS Build Script${NC}"
echo -e "${CYAN}========================================${NC}"

# Detect Apple Silicon
if [[ $(uname -m) == "arm64" && "$ARCH" == "amd64" ]]; then
    echo -e "${YELLOW}Detected Apple Silicon Mac${NC}"
    echo -e "${GRAY}Building for Intel (amd64) - use --arch arm64 for native builds${NC}"
fi

# Application configurations
declare -A apps=(
    ["snmptk"]="SNMP Tool Kit:cmd/snmptk:snmptk-mac:gui"
    ["scanner"]="Network Scanner:cmd/scanner:snmptk-scan-mac:gui"
    ["scanner-ext"]="Enhanced Scanner:cmd/scanner-ext:snmptk-scan-ext-mac:gui"
    ["report"]="Report Generator:cmd/report-generator:snmptk-report-mac:console"
)

# Function to clean builds
clean_builds() {
    echo -e "${YELLOW}Cleaning previous builds...${NC}"
    
    for app in "${!apps[@]}"; do
        IFS=':' read -r name path output type <<< "${apps[$app]}"
        if [ -f "$path/$app" ] || [ -f "$path/main" ]; then
            rm -f "$path/$app" "$path/main"
            echo -e "${GRAY}  Cleaned $path${NC}"
        fi
    done
    
    if [ -d "dist" ]; then
        rm -f dist/*-mac* dist/*.app
        rm -rf dist/*.app
        echo -e "${GRAY}  Cleaned dist directory${NC}"
    fi
}

# Function to install/update tools
update_tools() {
    echo -e "${YELLOW}Updating build tools...${NC}"
    
    # Check if Go is installed
    if ! command -v go &> /dev/null; then
        echo -e "${RED}Go is not installed or not in PATH${NC}"
        echo -e "${YELLOW}Install Go from: https://golang.org/dl/${NC}"
        exit 1
    fi
    
    echo -e "${GRAY}  Go version: $(go version)${NC}"
    
    # Check for Xcode command line tools (required for CGO)
    if ! xcode-select -p &> /dev/null; then
        echo -e "${YELLOW}  Xcode command line tools not found${NC}"
        echo -e "${GRAY}  Installing Xcode command line tools...${NC}"
        xcode-select --install
        echo -e "${YELLOW}  Please rerun this script after installation completes${NC}"
        exit 1
    fi
    
    # Update Fyne tools
    echo -e "${GRAY}  Installing Fyne tools...${NC}"
    go install fyne.io/tools/cmd/fyne@latest
    
    # Add Go bin to PATH if not already there
    export PATH=$PATH:$(go env GOPATH)/bin
    
    # Verify fyne command is available
    if ! command -v fyne &> /dev/null; then
        echo -e "${RED}Fyne command not found after installation${NC}"
        echo -e "${YELLOW}Make sure $(go env GOPATH)/bin is in your PATH${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}  Tools updated successfully${NC}"
}

# Function to build a single application
build_app() {
    local app_key=$1
    IFS=':' read -r app_name app_path output_name app_type <<< "${apps[$app_key]}"
    
    echo -e "\n${YELLOW}Building $app_name...${NC}"
    
    # Check if source exists
    if [ ! -f "$app_path/main.go" ]; then
        echo -e "${RED}  ERROR: main.go not found in $app_path${NC}"
        return 1
    fi
    
    if [ "$app_type" = "gui" ]; then
        # Use Fyne for GUI applications
        echo -e "${GRAY}  Building GUI application with Fyne...${NC}"
        
        # Set architecture-specific flags
        export CGO_ENABLED=1
        if [ "$ARCH" = "arm64" ]; then
            export GOARCH=arm64
            if [[ $(uname -m) != "arm64" ]]; then
                echo -e "${YELLOW}  Cross-compiling to ARM64 from Intel${NC}"
                export CGO_CFLAGS="-arch arm64"
                export CGO_LDFLAGS="-arch arm64"
            fi
        else
            export GOARCH=amd64
            if [[ $(uname -m) == "arm64" ]]; then
                echo -e "${YELLOW}  Cross-compiling to Intel from ARM64${NC}"
                export CGO_CFLAGS="-arch x86_64"
                export CGO_LDFLAGS="-arch x86_64"
            fi
        fi
        
        fyne package --target darwin --src "./$app_path"
        
        # Find the generated executable
        if [ -f "$app_path/$app_key" ]; then
            mv "$app_path/$app_key" "dist/$output_name"
        elif [ -f "$app_path/main" ]; then
            mv "$app_path/main" "dist/$output_name"
        elif [ -f "$app_path/$(basename $app_path)" ]; then
            mv "$app_path/$(basename $app_path)" "dist/$output_name"
        else
            echo -e "${RED}  ERROR: Generated executable not found${NC}"
            return 1
        fi
        
        # Create .app bundle if requested
        if [ "$CREATE_BUNDLE" = true ]; then
            echo -e "${GRAY}  Creating app bundle...${NC}"
            local bundle_name="${app_key}-mac.app"
            fyne package -os darwin -o "dist/$bundle_name" "./$app_path"
            
            if [ -d "dist/$bundle_name" ]; then
                echo -e "${GREEN}    ✓ App bundle created: dist/$bundle_name${NC}"
                
                # Set proper permissions
                chmod +x "dist/$bundle_name/Contents/MacOS/"*
                
                # Code signing (if developer tools available)
                if command -v codesign &> /dev/null; then
                    echo -e "${GRAY}    Attempting to code sign...${NC}"
                    codesign --force --deep --sign - "dist/$bundle_name" 2>/dev/null || \
                        echo -e "${YELLOW}    Code signing failed (requires valid certificate)${NC}"
                fi
            else
                echo -e "${YELLOW}    ⚠ App bundle creation failed${NC}"
            fi
        fi
        
    else
        # Use standard go build for console applications
        echo -e "${GRAY}  Building console application...${NC}"
        (
            cd "$app_path"
            CGO_ENABLED=0 GOARCH=$ARCH go build -ldflags "-s -w" -o "../../dist/$output_name" .
        )
    fi
    
    if [ -f "dist/$output_name" ]; then
        chmod +x "dist/$output_name"
        local size=$(du -h "dist/$output_name" | cut -f1)
        echo -e "${GREEN}  SUCCESS: $app_name ($size)${NC}"
        return 0
    else
        echo -e "${RED}  FAILED: $app_name${NC}"
        return 1
    fi
}

# Function to test builds
test_builds() {
    echo -e "\n${YELLOW}Testing builds...${NC}"
    
    for app_key in "${!apps[@]}"; do
        IFS=':' read -r app_name app_path output_name app_type <<< "${apps[$app_key]}"
        local output_path="dist/$output_name"
        
        if [ -f "$output_path" ]; then
            echo -e "${GRAY}  Testing $app_name...${NC}"
            
            # Check architecture
            local file_arch=$(file "$output_path" | grep -o "arm64\|x86_64" || echo "unknown")
            echo -e "${GRAY}    Architecture: $file_arch${NC}"
            
            if [ "$app_type" = "console" ]; then
                # Test console apps
                if timeout 5s "$output_path" --help &>/dev/null || [ $? -eq 124 ]; then
                    echo -e "${GREEN}    ✓ Console app responds correctly${NC}"
                else
                    echo -e "${YELLOW}    ⚠ Console app test inconclusive${NC}"
                fi
            else
                # For GUI apps, check if they can be executed
                echo -e "${GREEN}    ✓ GUI executable created${NC}"
                
                # Test app bundle if it exists
                local bundle_path="dist/${app_key}-mac.app"
                if [ -d "$bundle_path" ]; then
                    echo -e "${GREEN}    ✓ App bundle available${NC}"
                    echo -e "${GRAY}      Run: open dist/${app_key}-mac.app${NC}"
                fi
            fi
        fi
    done
}

# Function to show results
show_results() {
    echo -e "\n${CYAN}========================================${NC}"
    echo -e "${CYAN}Build Results:${NC}"
    echo -e "${CYAN}========================================${NC}"
    
    if [ -d "dist" ]; then
        local total_size=0
        local has_files=false
        
        # Show executables
        for file in dist/*-mac; do
            if [ -f "$file" ]; then
                has_files=true
                local size_bytes=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null)
                local size_readable=$(du -h "$file" | cut -f1)
                echo -e "${NC}  $(basename "$file") - $size_readable${NC}"
                if [[ "$size_bytes" =~ ^[0-9]+$ ]]; then
                    total_size=$((total_size + size_bytes))
                fi
            fi
        done
        
        # Show app bundles
        for bundle in dist/*.app; do
            if [ -d "$bundle" ]; then
                has_files=true
                local size_readable=$(du -sh "$bundle" | cut -f1)
                echo -e "${NC}  $(basename "$bundle") - $size_readable (bundle)${NC}"
            fi
        done
        
        if [ "$has_files" = false ]; then
            echo -e "${RED}  No files created${NC}"
        elif [ $total_size -gt 0 ]; then
            local total_mb=$(echo "scale=2; $total_size / 1048576" | bc -l 2>/dev/null || echo "?.?")
            echo -e "\n${CYAN}  Total executable size: ${total_mb} MB${NC}"
        fi
    else
        echo -e "${RED}  No files created${NC}"
    fi
    
    echo -e "\n${GREEN}Usage Examples:${NC}"
    echo -e "${GRAY}  ./dist/snmptk-mac                 # Main SNMP toolkit${NC}"
    echo -e "${GRAY}  ./dist/snmptk-scan-mac            # Basic network scanner${NC}"
    echo -e "${GRAY}  ./dist/snmptk-scan-ext-mac        # Enhanced scanner${NC}"
    echo -e "${GRAY}  ./dist/snmptk-report-mac <file>   # Generate reports${NC}"
    
    if [ "$CREATE_BUNDLE" = true ]; then
        echo -e "\n${GREEN}App Bundles:${NC}"
        echo -e "${GRAY}  open dist/snmptk-mac.app          # Launch SNMP toolkit${NC}"
        echo -e "${GRAY}  open dist/scanner-mac.app         # Launch scanner${NC}"
        echo -e "${GRAY}  open dist/scanner-ext-mac.app     # Launch enhanced scanner${NC}"
    fi
    
    if [ "$ARCH" = "arm64" ]; then
        echo -e "\n${YELLOW}Note: Built for Apple Silicon (ARM64)${NC}"
    else
        echo -e "\n${YELLOW}Note: Built for Intel (x86_64)${NC}"
    fi
    
    echo -e "\n${CYAN}macOS Tips:${NC}"
    echo -e "${GRAY}  • First run may require right-click -> Open due to Gatekeeper${NC}"
    echo -e "${GRAY}  • App bundles provide better integration with macOS${NC}"
    echo -e "${GRAY}  • Use 'codesign' for distribution outside development${NC}"
}

# Main execution
main() {
    # Clean if requested
    if [ "$CLEAN" = true ]; then
        clean_builds
        if [ "$TARGET" = "clean" ]; then
            exit 0
        fi
    fi
    
    # Create dist directory
    mkdir -p dist
    
    # Update tools
    update_tools
    
    # Build applications
    local build_success=0
    local build_total=0
    
    if [ "$TARGET" = "all" ]; then
        for app_key in "${!apps[@]}"; do
            build_total=$((build_total + 1))
            if build_app "$app_key"; then
                build_success=$((build_success + 1))
            fi
        done
    elif [[ -n "${apps[$TARGET]}" ]]; then
        build_total=1
        if build_app "$TARGET"; then
            build_success=1
        fi
    else
        echo -e "${RED}Invalid target: $TARGET${NC}"
        echo -e "${YELLOW}Valid targets: all, $(echo "${!apps[@]}" | tr ' ' ',')"
        exit 1
    fi
    
    # Test builds if requested
    if [ "$TEST" = true ]; then
        test_builds
    fi
    
    # Show results
    show_results
    
    # Summary
    echo -e "\n${CYAN}========================================${NC}"
    if [ $build_success -eq $build_total ]; then
        echo -e "${GREEN}✓ All builds completed successfully ($build_success/$build_total)${NC}"
    else
        echo -e "${YELLOW}⚠ Some builds failed ($build_success/$build_total)${NC}"
    fi
    echo -e "${CYAN}========================================${NC}"
}

# Run main function
main "$@"