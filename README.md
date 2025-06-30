# Go SNMP Tool Kit

A comprehensive SNMP testing and network discovery suite built in Go with modern GUI interfaces. This toolkit provides enterprise-grade network device discovery, SNMP operations, vendor-specific fingerprinting, and advanced network scanning capabilities with data persistence.

![Screenshot](https://raw.githubusercontent.com/scottpeterman/gosnmptk/refs/heads/main/screenshots/screens1.gif)

## Download and Installation

### Windows - Ready to Use
| Platform | Direct Download |
|----------|----------------|
| **Windows** | [Download snmptk.zip](https://github.com/scottpeterman/gosnmptk/raw/refs/heads/main/dist/snmptk.zip) |

**Windows users**: Download and run - no installation required. Contains all four applications.

### Linux and macOS - Build from Source
Other platforms require building from source using the included build scripts:

```bash
# Clone repository
git clone https://github.com/scottpeterman/gosnmptk.git
cd gosnmptk

# Linux/WSL2
./build_linux.sh --target all

# macOS (requires actual Mac hardware)
./build_mac.sh --target all
```

See the [Building Applications](#building-applications) section for detailed instructions.

## Suite Overview

The Go SNMP Tool Kit consists of four specialized applications:

### 1. SNMP Tool Kit (`snmptk`)
**Interactive SNMP client with vendor fingerprinting**
- Individual device testing and analysis
- Comprehensive vendor detection
- SNMP operations (GET, WALK, BULK)
- Real-time results with detailed logging

### 2. Network Scanner (`scanner`)
**Basic network discovery tool**
- CIDR-based network scanning
- Concurrent host discovery
- SNMP capability detection
- Simple CSV export

### 3. Enhanced Network Scanner (`scanner-ext`)
**Advanced network scanner with persistence**
- High-performance concurrent scanning
- Device persistence and deduplication
- Vendor fingerprinting integration
- Database aggregation and reporting
- Dynamic timeout scaling based on network size

### 4. Report Generator (`report`)
**Analytics and reporting tool**
- Device database analysis
- Network topology insights
- Performance metrics
- CSV export and data visualization

## Core Features

### Comprehensive Vendor Fingerprinting
- **Supported Vendors**: Cisco Systems, Dell Technologies (iDRAC), Arista Networks, Aruba Networks (HPE), HP Printers, HP Network Interfaces, Fortinet, Palo Alto Networks, Palo Alto SD-WAN (CloudGenix/Prisma), APC (Schneider Electric), Lexmark International
- **Smart Detection**: Multi-layer vendor detection using system descriptors, enterprise OIDs, and vendor-specific patterns
- **Device Type Recognition**: Automatic classification of switches, routers, firewalls, servers, printers, wireless controllers, UPS systems, PDUs, and SD-WAN gateways
- **Rich Data Extraction**: Model numbers, serial numbers, firmware versions, hardware revisions, service tags, and device-specific configurations

### SNMP Operations
- **Protocol Support**: SNMPv2c and SNMPv3 with comprehensive authentication options
- **Authentication Protocols**: MD5, SHA, SHA224, SHA256, SHA384, SHA512
- **Privacy Protocols**: DES, AES128, AES192, AES256
- **Operations**: GET, GETNEXT, GETBULK, WALK with configurable parameters

### Network Scanning Capabilities
- **Concurrent Processing**: Configurable concurrency levels for optimal performance
- **CIDR Support**: Full subnet scanning with automatic IP range generation
- **Dynamic Timeouts**: Intelligent timeout scaling based on network size
- **Connectivity Testing**: Multi-port TCP connectivity verification
- **Performance Optimization**: Device-friendly scanning to prevent agent overload

### Data Persistence and Analytics
- **Device Database**: Persistent storage with deduplication
- **Scan History**: Complete audit trail of discovery sessions
- **Aggregate Reporting**: Network-wide statistics and trends
- **Export Capabilities**: CSV and JSON export formats

## Architecture

```
gosnmptk/
├── cmd/
│   ├── snmptk/           # Interactive SNMP toolkit
│   ├── scanner/          # Basic network scanner
│   ├── scanner-ext/      # Enhanced scanner with persistence
│   └── report-generator/ # Analytics and reporting
├── pkg/
│   ├── fingerprint/      # Vendor detection engine
│   ├── persistence/      # Data storage and management
│   └── snmp/            # SNMP protocol implementation
├── config/              # YAML vendor configurations
├── dist/               # Build outputs
└── internal/           # Internal resources and utilities
```

### Core Components

#### Fingerprinting Engine (`pkg/fingerprint/`)
- **YAML-Based Configuration**: Extensible vendor definitions without code changes
- **Detection Algorithms**: Pattern matching and OID-based identification
- **Confidence Scoring**: Multi-factor confidence assessment

#### Persistence Layer (`pkg/persistence/`)
- **Device Management**: Automatic deduplication and aggregation
- **Session Tracking**: Complete scan history and statistics
- **Data Export**: Flexible export formats for integration

#### SNMP Implementation (`pkg/snmp/`)
- **Protocol Handling**: Complete SNMPv2c and SNMPv3 support
- **Connection Management**: Robust timeout and retry mechanisms
- **Error Recovery**: Graceful handling of device communication issues

## Installation and Setup

### Prerequisites
- Go 1.24.2 or later
- Git (for source installation)

### Quick Start
```bash
# Clone the repository
git clone https://github.com/scottpeterman/gosnmptk.git
cd gosnmptk

# Install dependencies
go mod download

# Run any application directly
go run ./cmd/snmptk          # Interactive toolkit
go run ./cmd/scanner         # Basic scanner
go run ./cmd/scanner-ext     # Enhanced scanner
go run ./cmd/report-generator # Report generator
```

## Building Applications

### All Platforms
The suite includes enhanced build scripts for consistent cross-platform compilation:

```bash
# Windows (PowerShell)
.\build_windows.ps1 -Target all -Clean -Test

# Linux/WSL2
./build_linux.sh --target all --clean --test

# macOS
./build_mac.sh --target all --clean
```

### Individual Application Builds
```bash
# Build specific applications
.\build_windows.ps1 -Target snmptk
./build_linux.sh --target scanner-ext
./build_mac.sh --target report
```

### Build Outputs
```
dist/
├── snmptk-windows.exe         # Interactive toolkit
├── snmptk-scan.exe           # Basic scanner
├── snmptk-scan-ext.exe       # Enhanced scanner
├── snmptk-report.exe         # Report generator
├── snmptk-linux              # Linux binaries
├── snmptk-scan-linux
├── snmptk-scan-ext-linux
├── snmptk-report-linux
├── snmptk-mac                # macOS binaries
├── snmptk-scan-mac
├── snmptk-scan-ext-mac
└── snmptk-report-mac
```

## Usage Guide

### SNMP Tool Kit
**Interactive device testing and fingerprinting**

1. **Connection Setup**
   - Configure device IP and SNMP credentials
   - Test connectivity before operations
   - Settings automatically saved between sessions

2. **SNMP Operations**
   - Execute individual SNMP commands
   - Test common MIB-II OIDs
   - Custom OID queries

3. **Vendor Fingerprinting**
   - Quick vendor detection for rapid identification
   - Full fingerprinting for comprehensive device data
   - Vendor-specific OID collection

### Network Scanner
**Basic network discovery**

1. **Network Configuration**
   - Enter CIDR notation for target network
   - Configure scan parameters (timeout, concurrency)
   - Set SNMP community strings

2. **Scanning Process**
   - Real-time progress monitoring
   - Live results display
   - Export to CSV format

### Enhanced Network Scanner
**Advanced scanning with persistence**

1. **Scan Configuration**
   - Network targeting with CIDR support
   - Advanced SNMP authentication
   - Fingerprinting options

2. **Performance Settings**
   - Dynamic timeout scaling
   - Configurable concurrency levels
   - Device-friendly scanning modes

3. **Data Management**
   - Automatic device persistence
   - Database aggregation
   - Historical scan tracking

4. **Analysis and Export**
   - Real-time device discovery
   - Aggregate device view
   - Comprehensive export options

### Report Generator
**Database analysis and reporting**

```bash
# Generate comprehensive reports
./snmptk-report devices.json

# Export to CSV
./snmptk-report devices.json export.csv
```

**Report Capabilities:**
- Device inventory analysis
- Vendor distribution statistics
- Network topology insights
- Scan performance metrics
- Subnet density analysis

## Technical Implementation

### Serial Processing for Device Safety
The toolkit uses serial SNMP processing to ensure maximum device compatibility:

```go
// Device-friendly sequential processing
for _, oidEntry := range prioritizedOIDs {
    value, err := client.Get(oidEntry.OID)
    if err == nil && IsValidSNMPValue(value) {
        results[oidEntry.Name] = value
    }
    time.Sleep(100 * time.Millisecond) // Gentle delay
}
```

### Dynamic Network Scaling
Enhanced scanner automatically adjusts parameters based on network size:

```go
// Intelligent timeout scaling
switch {
case ipCount > 32000: maxScanTime = 4 * time.Hour
case ipCount > 16000: maxScanTime = 2 * time.Hour
case ipCount > 8000:  maxScanTime = 1 * time.Hour
default:              maxScanTime = 10 * time.Minute
}
```

### Device Persistence and Deduplication
Automatic device management with intelligent merging:

```go
// Smart device deduplication
func (pb *PersistenceBridge) deduplicateDevices() {
    // Merge devices by system name
    // Combine IP addresses and interface data
    // Preserve scan history and confidence scores
}
```

## Vendor Extension System

### YAML-Based Configuration
The toolkit uses a completely user-editable YAML configuration file (`config/vendor_fingerprints.yaml`) for vendor detection. This allows adding new vendors without code changes.

### Adding New Vendors
To add support for a new vendor, edit the YAML file:

```yaml
vendors:
  your_vendor:
    display_name: "Your Vendor Name"
    enterprise_oid: "1.3.6.1.4.1.XXXXX"
    detection_patterns:
      - "vendor_pattern"
      - "product_name"
    oid_patterns:
      - "1.3.6.1.4.1.XXXXX."
      - "specific_keyword"
    device_types:
      - "switch"
      - "router"
    exclusion_patterns:
      - "avoid_this_pattern"  # Prevent false positives
    fingerprint_oids:
      - name: "Model Name"
        oid: "1.3.6.1.4.1.XXXXX.X.X.X"
        priority: 1
        description: "Device model identifier"
      - name: "Serial Number"
        oid: "1.3.6.1.4.1.XXXXX.X.X.Y"
        priority: 1
        description: "Device serial number"
```

### Detection Priority
The system uses priority-based detection to handle vendor conflicts:

```yaml
detection_rules:
  priority_order:
    - "specific_vendor"    # Check specific vendors first
    - "general_vendor"     # Then general patterns
    - "fallback_vendor"    # Finally fallback detection
```

### Key Configuration Elements

**Detection Patterns**: Text patterns found in system descriptions
**OID Patterns**: SNMP OID prefixes or keywords for vendor identification  
**Exclusion Patterns**: Patterns that disqualify vendor detection (prevents false positives)
**Priority Ordering**: Controls which vendor is checked first for ambiguous devices
**Fingerprint OIDs**: Vendor-specific OIDs to query for detailed device information

### Testing New Configurations
1. Edit `config/vendor_fingerprints.yaml`
2. Restart the application (YAML is loaded at startup)
3. Use "Test All Vendors" to verify detection
4. Check results for conflicts or missed detections
5. Adjust priority order or exclusion patterns as needed

## Configuration

### Default Settings
```yaml
# Connection defaults
port: 161
timeout: 3.0
retries: 2
concurrency: 25

# SNMP defaults
communities: ["public", "private"]
version: "SNMPv2c"

# Fingerprinting
enabled: true
type: "basic"  # or "full"

# Scanning behavior
scanning:
  default_timeout: 30
  oid_query_timeout: 10
  delay_between_queries: 100
  max_concurrent_queries: 5
```

## Performance Characteristics

### Scanning Performance
- **Basic Scanner**: 10-15 IPs per second (standard settings)
- **Enhanced Scanner**: 15-20 IPs per second with optimization
- **Memory Usage**: 50-100MB typical operation
- **Device Impact**: Minimal due to serial processing approach

### Binary Sizes
- **Windows**: 45-50MB per application
- **Linux**: 40-45MB per application  
- **macOS**: 45-50MB per application

### Scaling Capabilities
- **Small Networks** (/24): Seconds to minutes
- **Medium Networks** (/20): 10-30 minutes
- **Large Networks** (/16): 1-4 hours with dynamic timeout scaling

## Troubleshooting

### Build Issues
**Cross-Platform Dependencies**
- Ensure Fyne tools are installed: `go install fyne.io/tools/cmd/fyne@latest`
- Linux: Install build-essential for CGO support
- Windows: Use native PowerShell build script
- macOS: Requires Xcode command line tools

### Runtime Issues
**SNMP Connectivity**
- Verify UDP port 161 accessibility
- Check firewall settings on both client and target
- Confirm SNMP service is enabled on target devices
- Test with standard SNMP tools for baseline connectivity

**Performance Issues**
- Reduce concurrency for older network equipment
- Increase timeouts for slow-responding devices
- Use basic fingerprinting instead of full for faster results
- Monitor network utilization during large scans

**Data Persistence**
- Ensure write permissions in application directory
- Check disk space for database files
- Verify JSON file integrity for report generation

## Development

### Contributing
```bash
# Development setup
git clone https://github.com/scottpeterman/gosnmptk.git
cd gosnmptk
go mod download

# Run applications in development
go run ./cmd/snmptk
go run ./cmd/scanner-ext

# Code formatting
go fmt ./...
goimports -w .
```

### Adding Vendor Support
1. **Update YAML Configuration**
   - Add vendor entry in `config/vendor_fingerprints.yaml`
   - Define detection patterns and OIDs
   - Set device type classifications

2. **Test Implementation**
   - Verify against actual hardware
   - Validate OID responses
   - Confirm device type detection

## Distribution

### End-User Instructions

**Windows**
1. Download executable from releases
2. Run directly - no installation required
3. Windows Defender may require approval for first run

**Linux**
1. Download binary and make executable: `chmod +x snmptk-*-linux`
2. Run from terminal or file manager
3. Dependencies included in static binary

**macOS**
1. Download binary and make executable: `chmod +x snmptk-*-mac`
2. First run requires right-click and "Open" to bypass Gatekeeper
3. Subsequent runs work normally

### Integration Options
- **CSV Export**: Standard format for integration with network management systems
- **JSON Export**: Structured data for custom processing
- **Command Line**: Report generator supports automation workflows
- **Database Files**: Direct access to persistence layer for advanced integration

## License

This project is released under the MIT License. See LICENSE file for details.

---

**Go SNMP Tool Kit** - Professional network discovery and device fingerprinting suite.