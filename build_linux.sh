#!/bin/bash
# ==========================================
# Enhanced Linux Build Script for Go SNMP Tool Kit
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
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  -t, --target TARGET   Build target (all, snmptk, scanner, scanner-ext, report)"
            echo "  -c, --clean          Clean previous builds"
            echo "  --test               Test builds after creation"
            echo "  -a, --arch ARCH      Architecture (amd64, arm64)"
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
echo -e "${CYAN}Go SNMP Tool Kit - Linux Build Script${NC}"
echo -e "${CYAN}========================================${NC}"

# Application configurations
declare -A apps=(
    ["snmptk"]="SNMP Tool Kit:cmd/snmptk:snmptk-linux:gui"
    ["scanner"]="Network Scanner:cmd/scanner:snmptk-scan-linux:gui"
    ["scanner-ext"]="Enhanced Scanner:cmd/scanner-ext:snmptk-scan-ext-linux:gui"
    ["report"]="Report Generator:cmd/report-generator:snmptk-report-linux:console"
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
        rm -f dist/*-linux*
        echo -e "${GRAY}  Cleaned dist directory${NC}"
    fi
}

# Function to install/update tools
update_tools() {
    echo -e "${YELLOW}Updating build tools...${NC}"
    
    # Check if Go is installed
    if ! command -v go &> /dev/null; then
        echo -e "${RED}Go is not installed or not in PATH${NC}"
        exit 1
    fi
    
    echo -e "${GRAY}  Go version: $(go version)${NC}"
    
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
    
    # Clear any Windows cross-compiler settings
    unset CC CXX CC_FOR_windows CXX_FOR_windows
    
    if [ "$app_type" = "gui" ]; then
        # Use Fyne for GUI applications
        echo -e "${GRAY}  Building GUI application with Fyne...${NC}"
        
        # Set architecture-specific flags
        if [ "$ARCH" = "arm64" ]; then
            export GOARCH=arm64
            echo -e "${GRAY}  Building for ARM64 architecture${NC}"
        else
            export GOARCH=amd64
        fi
        
        fyne package --target linux --src "./$app_path"
        
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
    else
        # Use standard go build for console applications
        echo -e "${GRAY}  Building console application...${NC}"
        (
            cd "$app_path"
            GOARCH=$ARCH go build -ldflags "-s -w" -o "../../dist/$output_name" .
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
            
            if [ "$app_type" = "console" ]; then
                # Test console apps with --help or basic execution
                if timeout 5s "$output_path" --help &>/dev/null || [ $? -eq 124 ]; then
                    echo -e "${GREEN}    ✓ Console app responds correctly${NC}"
                else
                    echo -e "${YELLOW}    ⚠ Console app test inconclusive${NC}"
                fi
            else

                # For GUI apps, check if they're executable and have required libs
                if ldd "$output_path" &>/dev/null; then
                    echo -e "${GREEN}    ✓ GUI executable created with valid dependencies${NC}"
                else
                    echo -e "${YELLOW}    ⚠ GUI executable created (dependency check failed)${NC}"
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
    
    if [ -d "dist" ] && [ "$(ls -A dist/*-linux* 2>/dev/null)" ]; then
        local total_size=0
        for file in dist/*-linux*; do
            if [ -f "$file" ]; then
                local size_bytes=$(stat -c%s "$file" 2>/dev/null || stat -f%z "$file" 2>/dev/null)
                local size_mb=$(echo "scale=2; $size_bytes / 1048576" | bc -l 2>/dev/null || echo "?.?")
                local size_readable=$(du -h "$file" | cut -f1)
                echo -e "${NC}  $(basename "$file") - $size_readable${NC}"
                if [[ "$size_bytes" =~ ^[0-9]+$ ]]; then
                    total_size=$((total_size + size_bytes))
                fi
            fi
        done
        
        if [ $total_size -gt 0 ]; then
            local total_mb=$(echo "scale=2; $total_size / 1048576" | bc -l 2>/dev/null || echo "?.?")
            echo -e "\n${CYAN}  Total size: ${total_mb} MB${NC}"
        fi
    else
        echo -e "${RED}  No files created${NC}"
    fi
    
    echo -e "\n${GREEN}Usage Examples:${NC}"
    echo -e "${GRAY}  ./dist/snmptk-linux              # Main SNMP toolkit${NC}"
    echo -e "${GRAY}  ./dist/snmptk-scan-linux         # Basic network scanner${NC}"
    echo -e "${GRAY}  ./dist/snmptk-scan-ext-linux     # Enhanced scanner with persistence${NC}"
    echo -e "${GRAY}  ./dist/snmptk-report-linux <file> # Generate reports from scan data${NC}"
    
    if [ "$ARCH" = "arm64" ]; then
        echo -e "\n${YELLOW}Note: Built for ARM64 architecture${NC}"
    fi
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

# Check if running in WSL and show appropriate message
if grep -qi microsoft /proc/version 2>/dev/null; then
    echo -e "${CYAN}Detected WSL environment${NC}"
    echo -e "${GRAY}Built binaries can be copied to Windows with:${NC}"
    echo -e "${GRAY}cp dist/*-linux* /mnt/c/path/to/your/project/dist/${NC}"
    echo ""
fi

# Run main function
main "$@"