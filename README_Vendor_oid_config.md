# Vendor Fingerprints Configuration (vendor_fingerprints.yaml)

## Overview

The `vendor_fingerprints.yaml` file is the core configuration for SNMP-based network device vendor detection and fingerprinting. This file defines how the scanner identifies different network devices, what SNMP OIDs to query for detailed information, and how to classify devices by type.

## File Location

The configuration loader searches for the YAML file in the following locations (in order):

1. `./vendor_fingerprints.yaml` (same directory as executable)
2. `./config/vendor_fingerprints.yaml` (config subdirectory)
3. `/etc/snmp-fingerprint/vendor_fingerprints.yaml` (system-wide)
4. `~/.snmp-fingerprint/vendor_fingerprints.yaml` (user-specific)

## File Structure

### Top-Level Sections

```yaml
version: "1.0"                    # Configuration schema version
metadata: {...}                   # File metadata and documentation
common_oids: {...}               # Standard SNMP OIDs used across vendors
generic_oids: [...]              # Fallback OIDs for unknown devices
vendors: {...}                   # Vendor-specific configurations
detection_rules: {...}          # Detection priorities and confidence levels
scanning: {...}                 # SNMP scanning behavior configuration
```

## Section Details

### 1. Metadata Section

```yaml
metadata:
  description: "SNMP vendor fingerprinting configuration"
  last_updated: "2025-01-15"
  contributors: ["team", "community"]
```

**Purpose**: Documentation and version tracking  
**Required**: No  
**Dependencies**: None

### 2. Common OIDs Section

```yaml
common_oids:
  system_description: "1.3.6.1.2.1.1.1.0"  # sysDescr
  system_object_id: "1.3.6.1.2.1.1.2.0"    # sysObjectID
  system_name: "1.3.6.1.2.1.1.5.0"         # sysName
  # ... more standard MIB-II OIDs
```

**Purpose**: Standard SNMP OIDs used by all vendors  
**Required**: Yes (for basic device detection)  
**Dependencies**: SNMP MIB-II support on target devices

### 3. Generic OIDs Section

```yaml
generic_oids:
  - name: "Entity Model Name"
    oid: "1.3.6.1.2.1.47.1.1.1.1.13.1"
    priority: 1
    description: "Standard Entity MIB model name"
```

**Purpose**: Fallback OIDs for devices with unknown vendors  
**Required**: No (but recommended for better coverage)  
**Dependencies**: Entity MIB (RFC 4133) support on devices

### 4. Vendors Section

This is the core section defining vendor-specific detection and fingerprinting.

#### Vendor Configuration Structure

```yaml
vendors:
  vendor_key:                           # Internal vendor identifier
    display_name: "Human Readable Name" # Name shown to users
    enterprise_oid: "1.3.6.1.4.1.XXXX" # IANA enterprise OID
    detection_patterns: [...]           # Text patterns for identification
    oid_patterns: [...]                 # OID patterns for secondary detection
    device_types: [...]                 # Supported device types
    exclusion_patterns: [...]           # Patterns to exclude (optional)
    fingerprint_oids: [...]             # Vendor-specific OIDs to query
```

#### Required Fields

- **`display_name`**: Human-readable vendor name
- **`detection_patterns`**: List of text patterns found in sysDescr, sysContact, etc.
- **`fingerprint_oids`**: List of SNMP OIDs to query for detailed information

#### Optional Fields

- **`enterprise_oid`**: IANA-assigned enterprise OID
- **`oid_patterns`**: OID prefixes associated with this vendor
- **`device_types`**: Supported device types for classification
- **`exclusion_patterns`**: Patterns that disqualify vendor detection

#### Detection Patterns

Detection patterns are case-insensitive text strings searched in SNMP system fields:

```yaml
detection_patterns:
  - "cisco"                    # Matches "Cisco Systems" in sysDescr
  - "ios"                      # Matches "IOS Software" 
  - "catalyst"                 # Matches "Catalyst 2960"
  - "nx-os"                    # Matches "NX-OS"
```

**Search Fields** (in priority order):
1. `sysDescr` (1.3.6.1.2.1.1.1.0) - **High confidence**
2. `sysContact` (1.3.6.1.2.1.1.4.0) - **Medium confidence**
3. `sysName` (1.3.6.1.2.1.1.5.0) - **Low confidence**
4. `sysLocation` (1.3.6.1.2.1.1.6.0) - **Low confidence**

#### Exclusion Patterns

Prevent false positives by excluding certain patterns:

```yaml
hp_printer:
  detection_patterns:
    - "hewlett-packard"
  exclusion_patterns:
    - "switch"          # Don't detect HP switches as printers
    - "aruba"           # Don't detect Aruba devices as HP printers
```

#### Device Types

Classify devices into functional categories:

```yaml
device_types:
  - "switch"              # Network switch
  - "router"              # Network router  
  - "firewall"            # Security device
  - "wireless"            # Wireless equipment
  - "server"              # Server hardware
  - "printer"             # Printing device
  - "ups"                 # Uninterruptible power supply
  - "storage"             # Storage device
```

**Usage**: Device type inference uses:
1. Single type → Always assigned
2. Multiple types → Inferred from sysDescr patterns
3. No types → Falls back to "unknown"

#### Fingerprint OIDs

Vendor-specific SNMP OIDs for detailed device information:

```yaml
fingerprint_oids:
  - name: "Cisco IOS Version"              # Human-readable field name
    oid: "1.3.6.1.4.1.9.9.25.1.1.1.2.5"   # SNMP OID to query
    priority: 1                            # Query priority (1=highest)
    description: "IOS software version"    # Field description
    device_types: ["router", "switch"]     # Applicable device types (optional)
```

**Priority Levels**:
- **1-2**: Critical information (model, serial, version)
- **3-5**: Important details (firmware, hardware revision)
- **6-10**: Additional information (status, statistics)

**Device Type Filtering**: If specified, OID only queried for matching device types.

### 5. Detection Rules Section

```yaml
detection_rules:
  priority_order:                    # Vendor detection order
    - "hp_network"                   # Check HP network devices first
    - "hp_printer"                   # Then HP printers
    - "cisco"                        # Then Cisco devices
    # ... more vendors
  
  confidence_levels:                 # Confidence level definitions
    high: "Multiple vendor-specific OIDs successful"
    medium: "Basic detection + some vendor OIDs"
    low: "Basic detection only"
    none: "No vendor detected"
```

**Priority Order**: First match wins for ambiguous cases. Order matters for vendors that might conflict (e.g., HP networking vs HP printers).

### 6. Scanning Section

```yaml
scanning:
  default_timeout: 30              # Overall scan timeout (seconds)
  oid_query_timeout: 10            # Per-OID timeout (seconds)
  delay_between_queries: 100       # Delay between OIDs (milliseconds)
  max_concurrent_queries: 5        # Max concurrent SNMP operations
  retry_failed_oids: true          # Retry failed OID queries
  retry_count: 2                   # Number of retries for failed OIDs
```

**Purpose**: Controls SNMP scanning behavior and performance  
**Dependencies**: SNMP client timeout handling

## Dependencies

### Required Dependencies

1. **SNMP v2c/v3 Support**: Target devices must support SNMP
2. **MIB-II Support**: Standard system OIDs (1.3.6.1.2.1.1.x.0)
3. **YAML Parser**: Go application uses `gopkg.in/yaml.v3`

### Optional Dependencies

1. **Entity MIB (RFC 4133)**: For generic device information
2. **Vendor-Specific MIBs**: For detailed fingerprinting
3. **Interface MIB (RFC 2863)**: For interface information

### Network Requirements

1. **UDP Port 161**: SNMP queries (SNMPv2c/v3)
2. **Network Connectivity**: Scanner must reach target devices
3. **SNMP Community/Credentials**: Valid authentication

## Adding New Vendors

### 1. Identify Vendor Patterns

Scan a device and examine the output:

```bash
snmpwalk -v2c -c public 10.0.0.1 1.3.6.1.2.1.1.1.0
```

Look for vendor-specific text in the system description.

### 2. Add Vendor Configuration

```yaml
vendors:
  new_vendor:
    display_name: "New Vendor Inc."
    enterprise_oid: "1.3.6.1.4.1.12345"
    detection_patterns:
      - "new vendor"
      - "newvendor"
      - "product line name"
    device_types:
      - "switch"
      - "router"
    fingerprint_oids:
      - name: "Model Number"
        oid: "1.3.6.1.4.1.12345.1.1.1.0"
        priority: 1
        description: "Device model number"
```

### 3. Update Detection Priority

Add the vendor to the priority order:

```yaml
detection_rules:
  priority_order:
    - "new_vendor"        # Add here
    - "existing_vendor"
    # ... rest of list
```

### 4. Test Configuration

1. Save the YAML file
2. Restart the scanner application
3. Scan a device from the new vendor
4. Verify detection and fingerprinting results

## Troubleshooting

### Vendor Not Detected

1. **Check detection patterns**: Ensure patterns match actual sysDescr content
2. **Verify priority order**: Vendor must be listed in `detection_rules.priority_order`
3. **Check exclusion patterns**: Ensure exclusions aren't preventing detection
4. **Test SNMP connectivity**: Verify basic SNMP access to device

### Incorrect Device Type

1. **Review device_types list**: Ensure correct types are specified
2. **Check sysDescr patterns**: Verify description contains type indicators
3. **Update inference patterns**: Modify type detection logic if needed

### Missing Fingerprint Data

1. **Verify OID support**: Check if device supports vendor-specific MIBs
2. **Test OIDs manually**: Use snmpwalk to verify OID accessibility
3. **Check device permissions**: Ensure SNMP community has read access
4. **Review timeouts**: Increase timeout values for slow devices

### Configuration Errors

1. **YAML syntax**: Validate YAML format using online validators
2. **Required fields**: Ensure all required fields are present
3. **File location**: Verify file is in expected search path
4. **Restart required**: Configuration changes require application restart

## Performance Considerations

### OID Query Optimization

- **Prioritize critical OIDs**: Use priority 1-2 for essential information
- **Limit OID count**: Too many OIDs can slow scanning
- **Device-specific filtering**: Use `device_types` to reduce unnecessary queries

### Scanning Performance

- **Adjust timeouts**: Balance speed vs reliability
- **Concurrent queries**: Increase for faster scanning (if devices support it)
- **Delay settings**: Prevent overwhelming slow devices

### Memory Usage

- **Large configurations**: Consider impact on application memory
- **OID result caching**: Results cached during fingerprinting session

## Security Considerations

### SNMP Security

- **Community strings**: Use secure, non-default communities
- **SNMPv3**: Prefer SNMPv3 with authentication and encryption
- **Access control**: Limit SNMP access to management networks
- **Read-only access**: Fingerprinting only requires read access

### Configuration Security

- **File permissions**: Restrict access to configuration file
- **Sensitive OIDs**: Some OIDs may expose sensitive information
- **Logging**: Be careful logging SNMP data (may contain secrets)

## Examples

### Complete Vendor Example

```yaml
vendors:
  example_vendor:
    display_name: "Example Networks"
    enterprise_oid: "1.3.6.1.4.1.99999"
    detection_patterns:
      - "example networks"
      - "exampleos"
      - "example switch"
    oid_patterns:
      - "1.3.6.1.4.1.99999."
      - "example"
    device_types:
      - "switch"
      - "router"
    exclusion_patterns:
      - "emulator"        # Don't detect simulators
    fingerprint_oids:
      - name: "Software Version"
        oid: "1.3.6.1.4.1.99999.1.1.1.0"
        priority: 1
        description: "ExampleOS software version"
      - name: "Hardware Model"
        oid: "1.3.6.1.4.1.99999.1.1.2.0"
        priority: 1
        description: "Hardware model number"
        device_types: ["switch", "router"]
      - name: "Serial Number"
        oid: "1.3.6.1.4.1.99999.1.1.3.0"
        priority: 2
        description: "Device serial number"
```

