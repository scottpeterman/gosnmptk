# Go SNMP Tool Kit

A comprehensive SNMP testing and vendor fingerprinting toolkit built in Go with a modern GUI interface. This tool provides enterprise-grade network device discovery, SNMP operations, and vendor-specific fingerprinting capabilities with persistent user settings.

## Features

### 🔍 **Comprehensive Vendor Fingerprinting**
- **Supported Vendors**: Cisco, Dell (iDRAC), Arista, Aruba/HP ProCurve, Fortinet, Palo Alto, APC
- **Smart Detection**: Multi-layer vendor detection using sysDescr, sysContact, sysName, and vendor-specific OIDs
- **Device Type Recognition**: Distinguishes between device types (switches, servers, wireless controllers, etc.)
- **Rich Data Extraction**: Collects model numbers, serial numbers, firmware versions, hardware revisions

### 🛠 **SNMP Operations**
- **Full SNMP Support**: GET, GETNEXT, GETBULK, WALK operations
- **Protocol Support**: SNMPv2c and SNMPv3 with comprehensive crypto options
- **Authentication**: MD5, SHA, SHA224, SHA256, SHA384, SHA512
- **Privacy**: DES, AES128, AES192, AES256
- **Bulk Operations**: Test all common MIB-II OIDs with a single click

### 🚀 **Performance & Stability**
- **Serial Processing**: Stable, device-friendly approach that prevents SNMP agent overload
- **Configurable Timeouts**: Customizable timeout and retry settings
- **Progress Tracking**: Real-time feedback on fingerprinting progress
- **Error Handling**: Comprehensive error reporting and graceful failure handling

### 🎨 **Modern GUI Interface**
- **Tabbed Interface**: Organized workflow with Connection, Operations, Fingerprinting, and Results tabs
- **Real-time Results**: Live markdown-formatted results with color-coded status indicators
- **Credential Management**: Secure handling of SNMP credentials with password masking
- **Persistent Settings**: Automatically saves and restores connection settings between sessions
- **Export Ready**: Results formatted for easy copying and documentation

## Architecture

```
├── cmd/
│   └── snmptk/
│       ├── main.go          # GUI application entry point
│       └── Icon.png         # Application icon (auto-generated)
├── pkg/
│   ├── fingerprint/
│   │   ├── client.go         # Fingerprinting client and logic
│   │   └── detector.go       # Vendor detection and OID definitions
│   └── snmp/
│       └── client.go         # SNMP protocol implementation
├── dist/                     # Build output directory
├── build_windows.ps1         # Windows build script
├── build_linux.sh           # Linux build script (WSL2)
├── build_mac.sh             # macOS build script (macOS only)
└── go.mod
```

### Core Components

#### **Fingerprinting Engine** (`pkg/fingerprint/`)
- **Client**: Manages SNMP connections and orchestrates fingerprinting operations
- **Detector**: Contains vendor-specific detection patterns and OID definitions
- **Serial Processing**: Queries OIDs sequentially to ensure device stability

#### **SNMP Layer** (`pkg/snmp/`)
- **Protocol Handling**: SNMPv2c and SNMPv3 implementation
- **Authentication**: Comprehensive crypto protocol support
- **Connection Management**: Timeout, retry, and error handling

#### **GUI Application** (`cmd/snmptk/`)
- **Fyne Framework**: Modern, cross-platform GUI toolkit
- **Responsive Design**: Adaptive interface with real-time updates
- **State Management**: Proper handling of UI state and user interactions
- **Settings Persistence**: Automatic save/restore of user preferences

## Vendor-Specific Capabilities

### **Dell iDRAC Servers**
```
✅ Service Tag: FX84LM3
✅ Model: PowerEdge R650  
✅ iDRAC Version: 6.10.30.00
✅ BIOS Version: VMware ESXi
✅ System Status: OK
✅ iDRAC URL: https://10.35.190.178:443
```

### **Cisco Network Equipment**
```
✅ Model: C9407R
✅ Serial: FXS2516Q2GW
✅ IOS Version: CW_VERSION$17.9.6a$
✅ Software Version: CW_IMAGE$CAT9K_IOSXE$
✅ Hardware Version: V01
```

### **Arista Switches**
```
✅ Model: DCS-7050CX3-32S
✅ Serial: HBG242504MF
✅ EOS Version: [Detected from vendor OIDs]
✅ Hardware Revision: 12.02
✅ Architecture: [System architecture info]
```

### **Aruba/HP ProCurve**
```
✅ Model: Aruba JL357A Fixed 48G PoE+ 4SFP+ Module
✅ System Description: 2540-48G-PoE+-4SFP+ Switch
✅ ROM Version: YC.16.01.0003
✅ System Object ID: 1.3.6.1.4.1.11.2.3.7.11.182.21
```

## Installation & Setup

### Prerequisites
- Go 1.24.2 or later (tested on go1.24.2 windows/amd64)
- Git

### Quick Start
```bash
# Clone the repository
git clone https://github.com/scottpeterman/gosnmptk.git
cd gosnmptk

# Install dependencies
go mod download

# Run directly (development)
go run ./cmd/snmptk
```

## Building

### Windows (Native)
```powershell
# Quick build
go build -o snmptk.exe ./cmd/snmptk

# Or use the build script
.\build_windows.ps1
```

### Cross-Platform Building

#### Windows (Native)
```powershell
# Quick development build
go build -o snmptk.exe ./cmd/snmptk

# Production build with script
.\build_windows.ps1
```

#### Linux (WSL2 or Native Linux)
```bash
# Make script executable
chmod +x build_linux.sh

# Build Linux version
./build_linux.sh

# Cross-compile to Windows from Linux
export CC=x86_64-w64-mingw32-gcc
export CXX=x86_64-w64-mingw32-g++
fyne package --target windows --src ./cmd/snmptk
```

#### macOS (Native macOS Required)
```bash
# On actual macOS machine
chmod +x build_mac.sh
./build_mac.sh

# Or direct build
fyne package --target darwin --src ./cmd/snmptk
```

**Note**: Cross-compilation to macOS from Windows/Linux is not supported due to Apple toolchain requirements. Build on actual macOS hardware for best results.

### Cross-Platform Build Setup

#### Windows Development
- **Primary**: Native Windows builds using Fyne package tool
- **File**: `build_windows.ps1`
- **Output**: `dist/snmptk-windows.exe` (~49MB)

#### Linux via WSL2
- **Setup**: Install build-essential and gcc-mingw-w64 in WSL2
- **File**: `build_linux.sh` 
- **Cross-compile to Windows**: Possible with MinGW toolchain

#### macOS Native
- **Requirements**: Actual macOS machine with Xcode tools
- **File**: `build_mac.sh`
- **Cross-compilation**: Not supported from other platforms

## Usage Guide

### First Time Setup
1. **Launch the application**
2. **Connection Tab**: Enter your device IP and SNMP credentials
3. **Settings are automatically saved** for future sessions
4. **Test Connection** to verify connectivity

### Basic SNMP Testing

1. **Connection Setup**
   - Enter target IP address and port (default: 161)
   - Configure timeout (default: 5.0 seconds) and retries (default: 2)
   - Select SNMP version (v2c or v3)

2. **SNMPv2c Configuration**
   - Set community string (default: "public")

3. **SNMPv3 Configuration**
   - Username: SNMP v3 username
   - Auth Protocol: MD5, SHA, SHA224, SHA256, SHA384, SHA512
   - Auth Key: Authentication password
   - Priv Protocol: DES, AES128, AES192, AES256  
   - Priv Key: Privacy password

4. **Test Connection**
   - Click "Test Connection" to verify SNMP connectivity
   - Uses sysDescr OID (1.3.6.1.2.1.1.1.0) for validation

### SNMP Operations

1. **Select Operation Type**
   - **GET**: Retrieve specific OID value
   - **GETNEXT**: Get the next OID in the MIB tree
   - **GETBULK**: Retrieve multiple values efficiently
   - **WALK**: Traverse MIB subtree

2. **OID Selection**
   - Choose from predefined categories (Common MIB-II, vendor-specific)
   - Select from dropdown of common OIDs
   - Enter custom OID manually

3. **Execute Operations**
   - "Execute SNMP Operation": Run selected operation
   - "Test All Common OIDs": Bulk test of standard MIB-II OIDs
   - "Clear Results": Reset results display

### Vendor Fingerprinting

1. **Quick Vendor Detection**
   - Performs basic vendor identification using standard MIB-II data
   - Fast operation using sysDescr, sysContact, sysName analysis
   - Provides initial vendor confidence assessment

2. **Full Vendor Fingerprint (Serial)**
   - Comprehensive vendor-specific OID collection
   - Serial processing for maximum device compatibility
   - Detailed hardware/software information extraction
   - Progress tracking with real-time status updates

3. **Specialized Operations**
   - **Test All Vendors**: Compare fingerprinting across all supported vendors
   - **Dell iDRAC Fingerprint**: Focused Dell server identification

## Technical Implementation

### Persistent Settings
The application automatically saves connection settings using Fyne's built-in preferences system:
- **Windows**: Registry/AppData
- **macOS**: ~/Library/Preferences  
- **Linux**: ~/.config

Settings saved include:
- Connection details (IP, port, timeout, retries)
- SNMP version and credentials
- Protocol selections

### Serial Processing Architecture
The toolkit uses a **serial processing approach** instead of concurrent SNMP requests to ensure maximum compatibility with network devices:

```go
// Serial OID querying with proper delays
for i, oidEntry := range oids {
    c.log(fmt.Sprintf("Querying %d/%d: %s", i+1, len(oids), oidEntry.Name))
    
    value, err := c.snmpClient.Get(oidEntry.OID)
    if err == nil && IsValidSNMPValue(value) {
        fingerprintData[oidEntry.Name] = value
    }
    
    // Gentle delay between requests
    time.Sleep(100 * time.Millisecond)
}
```

### Smart Vendor Detection
Multi-layer detection algorithm with confidence scoring:

```go
// 1. Primary: sysDescr analysis (high confidence)
// 2. Secondary: sysContact patterns (medium confidence)  
// 3. Tertiary: sysName hostname analysis (low confidence)
// 4. Validation: Vendor-specific OID confirmation
```

### OID Prioritization System
Vendor-specific OIDs are prioritized to query most reliable information first:

```go
type OIDEntry struct {
    Name     string `json:"name"`
    OID      string `json:"oid"`
    Priority int    `json:"priority"` // 1=highest, 10=lowest
}
```

## Configuration

### Default Settings
```go
// Connection defaults
Port:    161
Timeout: 5.0 seconds
Retries: 2

// SNMPv2c defaults  
Community: "public"

// SNMPv3 defaults
AuthProtocol: SHA
PrivProtocol: AES128
```

### Build Requirements

#### Windows
- Go 1.24.2+
- Fyne tools: `go install fyne.io/tools/cmd/fyne@latest`

#### Linux/WSL2
- Go 1.24.2+
- build-essential: `sudo apt install build-essential`
- MinGW (for Windows cross-compilation): `sudo apt install gcc-mingw-w64`
- Fyne tools: `go install fyne.io/tools/cmd/fyne@latest`

#### macOS
- Go 1.24.2+
- Xcode command line tools
- Fyne tools: `go install fyne.io/tools/cmd/fyne@latest`

## Troubleshooting

### Build Issues

**Windows Cross-Compilation from WSL2**
```bash
# Install required tools
sudo apt update
sudo apt install build-essential gcc-mingw-w64

# Set cross-compiler
export CC=x86_64-w64-mingw32-gcc
export CXX=x86_64-w64-mingw32-g++

# Build
fyne package --target windows --src ./cmd/snmptk
```

**macOS Cross-Compilation**
- **Not supported** for GUI applications with CGO
- Requires actual macOS hardware with Xcode tools
- Apple restricts cross-compilation toolchains

**Icon Missing Error**
```bash
# Create placeholder icon
touch cmd/snmptk/Icon.png
# Or download a proper icon file
```

### Runtime Issues

**Connection Timeouts**
- Verify IP address and port accessibility
- Check firewall settings (UDP 161)
- Increase timeout value for slow devices
- Ensure SNMP is enabled on target device

**Authentication Failures (SNMPv3)**
- Verify username and credentials
- Check auth/priv protocol compatibility
- Ensure user has proper SNMP access rights
- Confirm engine ID synchronization

**Empty Fingerprint Results**
- Verify SNMP community/credentials
- Check if device supports vendor-specific MIBs
- Try "Test All Common OIDs" for basic connectivity
- Some devices may have limited MIB implementations

### Debug Tips

1. **Use Test Connection First**: Always verify basic SNMP connectivity
2. **Check Common OIDs**: Test standard MIB-II before vendor-specific
3. **Monitor Logs**: Watch real-time progress for failed OIDs
4. **Try Different Vendors**: Some devices may respond better to different vendor OID sets
5. **Adjust Timeouts**: Increase for slow or heavily loaded devices

## Performance Characteristics

### Timing Benchmarks
- **Quick Detection**: ~100ms (basic MIB-II only)
- **Full Fingerprinting**: 1-5 seconds (depending on vendor OID count)
- **Serial Processing**: 100ms delay between OID requests
- **Bulk Testing**: 30-60 seconds (all vendor fingerprints)

### Binary Sizes
- **Windows**: ~49MB (includes all dependencies)
- **Linux**: ~45MB (typical)
- **macOS**: ~50MB (with app bundle)

### Resource Usage
- **Memory**: ~50MB typical GUI application
- **Network**: Minimal bandwidth (small UDP packets)
- **CPU**: Low impact during serial processing
- **Device Load**: Minimal impact due to serial approach

## Development

### Contributing
```bash
# Setup development environment
git clone https://github.com/scottpeterman/gosnmptk.git
cd gosnmptk
go mod download

# Run in development mode
go run ./cmd/snmptk

# Format code
go fmt ./...

# Test builds
.\build_windows.ps1  # Windows
./build_linux.sh    # Linux/WSL2
```

### Adding New Vendors

1. **Add Detection Patterns**
```go
"newvendor": {
    DetectionPatterns: []string{"vendor", "product", "pattern"},
    FingerprintOIDs: []OIDEntry{
        {"Vendor Model", "1.3.6.1.4.1.XXXX.X.X.X.X", 1},
        // Add vendor-specific OIDs with priorities
    },
}
```

2. **Update Pattern Matching**
```go
"newvendor": {"1.3.6.1.4.1.XXXX.", "vendor", "keyword"},
```

3. **Test Thoroughly**: Verify against actual hardware

## Distribution

### File Structure
```
dist/
├── snmptk-windows.exe    # Windows executable (49MB)
├── snmptk-linux          # Linux executable (~45MB)
└── snmptk-mac            # macOS executable (~50MB)
```

### End-User Instructions

#### Windows
1. Download `snmptk-windows.exe`
2. Run directly - no installation required
3. Windows may show security warning (click "More info" → "Run anyway")

#### macOS
1. Download `snmptk-mac` 
2. Make executable: `chmod +x snmptk-mac`
3. First run: Right-click → "Open" (bypass Gatekeeper)
4. Subsequent runs: Double-click or `./snmptk-mac`

#### Linux
1. Download `snmptk-linux`
2. Make executable: `chmod +x snmptk-linux`
3. Run: `./snmptk-linux`

## License

This project is released under the MIT License. See LICENSE file for details.

## Acknowledgments

- **Fyne Framework**: Cross-platform GUI toolkit
- **Go SNMP Libraries**: SNMP protocol implementation
- **Network Vendor Documentation**: OID specifications and MIB references
- **Community Testing**: Real-world device validation
- **MinGW Project**: Windows cross-compilation toolchain

## Support

For issues, feature requests, or contributions:
- GitHub Issues: [Project Issues](https://github.com/scottpeterman/gosnmptk/issues)
- Documentation: This README and inline code comments
- Testing: Validate against your specific device models

---

**Go SNMP Tool Kit** - Professional network device discovery and fingerprinting made simple.