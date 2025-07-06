# Go SNMP Toolkit CLI

A powerful command-line network discovery and SNMP fingerprinting tool built for enterprise network environments. Designed for network engineers, security professionals, and automation workflows.

## Quick Start

```bash
# Basic network scan
gosnmpcli -mode scan -target 192.168.1.0/24

# Fast scan of large network
gosnmpcli -mode scan -target 10.0.0.0/16 -fast

# Export results to CSV
gosnmpcli -mode scan -target 192.168.1.0/24 -output csv -output-file devices.csv
```

## Installation

### Download Binary
```bash
# Download from releases
wget https://github.com/scottpeterman/gosnmptk/releases/latest/download/gosnmpcli-linux
chmod +x gosnmpcli-linux
```

### Build from Source
```bash
git clone https://github.com/scottpeterman/gosnmptk.git
cd gosnmptk
go build -o gosnmpcli ./cmd/cli/
```

## Core Features

- **High-Performance Scanning**: Concurrent discovery with intelligent rate limiting
- **YAML-Driven Vendor Detection**: Extensible vendor fingerprinting without code changes
- **Enterprise SNMP Support**: Full SNMPv2c and SNMPv3 with all crypto protocols
- **Multiple Output Formats**: JSON, CSV, table, and simple formats
- **Data Persistence**: Device database with deduplication and history
- **Network Intelligence**: Dynamic timeout scaling based on network size

## Command Reference

### Operation Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| `scan` | Network discovery with SNMP detection | Primary network mapping |
| `test` | Test SNMP connectivity to specific device | Troubleshooting individual devices |
| `fingerprint` | Enhanced vendor fingerprinting | Detailed device analysis |
| `discover` | Basic host discovery | Quick network overview |
| `query` | Custom OID queries | Specific SNMP data retrieval |

### Essential Options

```bash
# Network Targeting
-target "192.168.1.0/24"           # CIDR notation
-targets-file "hosts.txt"          # File with IP list

# SNMP Configuration
-communities "public,private"       # SNMPv2c communities
-snmp-version 3                    # SNMP version (1,2,3)
-username "admin"                  # SNMPv3 username
-auth-key "authpass"               # SNMPv3 auth password
-priv-key "privpass"               # SNMPv3 privacy password

# Performance Tuning
-concurrency 50                    # Concurrent operations
-timeout 3s                        # SNMP timeout
-fast                              # Fast mode preset

# Output Control
-output json                       # Output format
-output-file results.csv           # Save to file
-quiet                             # Suppress progress
-verbose                           # Detailed logging
```

## Usage Examples

### Basic Network Discovery

```bash
# Scan home network
gosnmpcli -mode scan -target 192.168.1.0/24

# Scan with custom communities
gosnmpcli -mode scan -target 10.0.0.0/24 -communities "public,private,community"

# Export to CSV for analysis
gosnmpcli -mode scan -target 192.168.1.0/24 -output csv -output-file network-inventory.csv
```

### Large Network Scanning

```bash
# Fast scan of /16 network (65k+ hosts)
gosnmpcli -mode scan -target 172.16.0.0/16 -fast -concurrency 100

# Corporate network with persistence
gosnmpcli -mode scan -target 10.0.0.0/8 \
  -enable-db -database corporate-devices.json \
  -output csv -output-file daily-scan.csv
```

### SNMPv3 Enterprise Scanning

```bash
# SNMPv3 with SHA/AES encryption
gosnmpcli -mode scan -target 192.168.100.0/24 \
  -snmp-version 3 \
  -username "netadmin" \
  -auth-protocol SHA256 \
  -auth-key "SecureAuthPass123" \
  -priv-protocol AES256 \
  -priv-key "SecurePrivPass456"

# Multiple targets from file
gosnmpcli -mode scan -targets-file critical-devices.txt \
  -snmp-version 3 -username admin -auth-key mypass -priv-key mypriv \
  -output json -output-file security-scan.json
```

### Device Testing and Troubleshooting

```bash
# Test specific device connectivity
gosnmpcli -mode test -target 192.168.1.10 -verbose

# Test with multiple communities
gosnmpcli -mode test -target 10.1.1.1 \
  -communities "public,private,network,cisco" \
  -details

# Custom OID query (example: interface table)
gosnmpcli -mode query -target 192.168.1.1 \
  -oid "1.3.6.1.2.1.2.2.1.2" \
  -operation walk
```

### Vendor-Specific Scanning

```bash
# Focus on Cisco devices
gosnmpcli -mode scan -target 10.0.0.0/16 \
  -vendor cisco \
  -fingerprint-type full \
  -config ./cisco-enhanced.yaml

# Filter by device type in output
gosnmpcli -mode scan -target 192.168.0.0/16 \
  -output csv \
  | grep -E "(switch|router)" > network-infrastructure.csv
```

### Automation and Integration

```bash
# Cron-friendly quiet mode
gosnmpcli -mode scan -target 10.0.0.0/24 \
  -quiet \
  -output csv \
  -output-file "/var/log/network/scan-$(date +%Y%m%d).csv"

# JSON output for API integration
gosnmpcli -mode scan -target 192.168.1.0/24 \
  -output json \
  -details | \
  jq '.[] | select(.detected_vendor == "cisco")' > cisco-devices.json

# Database aggregation
gosnmpcli -mode scan -target 10.0.0.0/16 \
  -enable-db -database /opt/network/devices.json \
  -quiet
```

## Configuration Files

### Vendor Fingerprints (vendor_fingerprints.yaml)

Place in one of these locations:
- `./vendor_fingerprints.yaml` (current directory)
- `./config/vendor_fingerprints.yaml`
- `~/.gosnmp/vendor_fingerprints.yaml`
- `/etc/gosnmp/vendor_fingerprints.yaml`

```yaml
version: "2.0"
vendors:
  myvendor:
    display_name: "My Network Vendor"
    enterprise_oid: "1.3.6.1.4.1.12345"
    detection_patterns:
      - "myvendor"
      - "custom device"
    device_types:
      - "switch"
      - "router"
    fingerprint_oids:
      - name: "Model"
        oid: "1.3.6.1.4.1.12345.1.1.1.0"
        priority: 1
```

### Target Lists (hosts.txt)

```
# Critical infrastructure
192.168.1.1     # Core router
192.168.1.10    # Primary switch
10.0.1.0/24     # Server subnet
172.16.5.100    # Firewall

# Data center
10.1.0.0/24
10.1.1.0/24
```

## Output Formats

### Table Format (Default)
```
IP Address      | Hostname           | Status | SNMP | Vendor | Model
192.168.1.1     | router.company.com | Up     | Yes  | cisco  | ISR4331
192.168.1.10    | sw-floor1         | Up     | Yes  | cisco  | CAT9300-48P
```

### JSON Format
```json
[
  {
    "ip": "192.168.1.1",
    "hostname": "router.company.com",
    "responding": true,
    "snmp_ready": true,
    "detected_vendor": "cisco",
    "device_type": "router",
    "model": "ISR4331",
    "serial_number": "FGL123456789",
    "firmware_version": "16.09.05"
  }
]
```

### CSV Format
```csv
IP,Hostname,Responding,SNMP_Ready,Vendor,Model
192.168.1.1,router.company.com,true,true,cisco,ISR4331
192.168.1.10,sw-floor1,true,true,cisco,CAT9300-48P
```

## Performance Tuning

### Network Size Optimization

```bash
# Small networks (/24, /25)
gosnmpcli -mode scan -target 192.168.1.0/24 -concurrency 25

# Medium networks (/20, /21)  
gosnmpcli -mode scan -target 10.1.0.0/20 -concurrency 50 -timeout 2s

# Large networks (/16 and bigger)
gosnmpcli -mode scan -target 172.16.0.0/16 -fast -concurrency 100
```

### Device-Specific Tuning

```bash
# Slow/old devices
gosnmpcli -mode scan -target 192.168.100.0/24 \
  -timeout 5s -retries 3 -concurrency 10

# High-performance environment
gosnmpcli -mode scan -target 10.0.0.0/16 \
  -timeout 1s -retries 1 -concurrency 200
```

## Troubleshooting

### Common Issues

**No SNMP responses**
```bash
# Test with verbose logging
gosnmpcli -mode test -target 192.168.1.1 -verbose

# Try different communities
gosnmpcli -mode test -target 192.168.1.1 \
  -communities "public,private,cisco,admin"
```

**Slow scanning**
```bash
# Check if timeout is too high
gosnmpcli -mode scan -target 192.168.1.0/24 -timeout 1s

# Reduce concurrency for stability
gosnmpcli -mode scan -target 10.0.0.0/24 -concurrency 10
```

**Memory usage on large scans**
```bash
# Use quiet mode and file output
gosnmpcli -mode scan -target 10.0.0.0/8 \
  -quiet -output csv -output-file results.csv
```

### Debugging Vendor Detection

```bash
# Verbose vendor detection
gosnmpcli -mode test -target 192.168.1.1 -verbose -details

# Test custom vendor config
gosnmpcli -mode scan -target 192.168.1.0/24 \
  -config ./debug-vendors.yaml -verbose
```

## Integration Examples

### Nagios/PRTG Integration
```bash
#!/bin/bash
# Monitor network changes
gosnmpcli -mode scan -target 10.0.0.0/24 \
  -quiet -output csv > current_scan.csv

diff previous_scan.csv current_scan.csv || \
  echo "CRITICAL: Network topology changed"
```

### Ansible Inventory Generation
```bash
# Generate dynamic inventory
gosnmpcli -mode scan -target 192.168.0.0/16 \
  -output json | \
  jq -r '.[] | select(.detected_vendor == "cisco") | .ip' > cisco_hosts.txt
```

### Security Scanning Integration
```bash
# Find SNMP-enabled devices for security audit
gosnmpcli -mode scan -target 10.0.0.0/8 \
  -communities "public,private,admin,cisco,secret" \
  -output csv | \
  awk -F, '$4=="true" {print $1}' > snmp_devices.txt
```

## Advanced Features

### Database Persistence
```bash
# Enable device database
gosnmpcli -mode scan -target 10.0.0.0/24 \
  -enable-db -database ./network.json

# View stored devices
cat network.json | jq '.devices[] | select(.vendor == "cisco")'
```

### Custom YAML Configuration
```bash
# Use custom vendor definitions
gosnmpcli -mode scan -target 192.168.1.0/24 \
  -config ./my-vendors.yaml \
  -fingerprint-type full
```

### Parallel Processing
```bash
# Split large networks for parallel processing
echo "10.0.0.0/18 10.64.0.0/18 10.128.0.0/18 10.192.0.0/18" | \
  tr ' ' '\n' | \
  xargs -n1 -P4 -I{} gosnmpcli -mode scan -target {} \
    -quiet -output csv -output-file scan-{}.csv
```

## Best Practices

1. **Start Small**: Test with /24 networks before scaling to /16
2. **Use Fast Mode**: For large networks, enable fast mode first
3. **Enable Persistence**: Use database for ongoing network management
4. **Monitor Progress**: Use verbose mode for initial testing
5. **Respect Devices**: Lower concurrency for older equipment
6. **Backup Configs**: Keep custom YAML configurations in version control
7. **Regular Scanning**: Automate scans for network change detection


---

**Go SNMP Toolkit CLI** - Enterprise network discovery from the command line.