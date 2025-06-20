package fingerprint

import (
	"fmt"
	"strings"
	"time"
)

// VendorFingerprint represents vendor-specific fingerprinting configuration
type VendorFingerprint struct {
	DetectionPatterns []string   `json:"detection_patterns"`
	FingerprintOIDs   []OIDEntry `json:"fingerprint_oids"`
}

// OIDEntry represents an OID with its description and priority
type OIDEntry struct {
	Name     string `json:"name"`
	OID      string `json:"oid"`
	Priority int    `json:"priority"` // 1=highest, 10=lowest
}

// FingerprintResult represents the result of vendor fingerprinting
type FingerprintResult struct {
	DetectedVendor  string            `json:"detected_vendor"`
	Confidence      string            `json:"confidence"`       // "high", "medium", "low", "none"
	DetectionMethod string            `json:"detection_method"` // "sysDescr", "sysContact", etc.
	FingerprintData map[string]string `json:"fingerprint_data"`
	ScanDuration    time.Duration     `json:"scan_duration"`
	Success         bool              `json:"success"`
	ErrorMessage    string            `json:"error_message,omitempty"`
}

// Common MIB-II OIDs for basic system information
var CommonOIDs = map[string]string{
	"System Description": "1.3.6.1.2.1.1.1.0",
	"System Object ID":   "1.3.6.1.2.1.1.2.0",
	"System Uptime":      "1.3.6.1.2.1.1.3.0",
	"System Contact":     "1.3.6.1.2.1.1.4.0",
	"System Name":        "1.3.6.1.2.1.1.5.0",
	"System Location":    "1.3.6.1.2.1.1.6.0",
	"System Services":    "1.3.6.1.2.1.1.7.0",
}

// VendorFingerprints contains fingerprinting data for different vendors
// Now with improved OID prioritization and vendor-specific focus
var VendorFingerprints = map[string]VendorFingerprint{
	"cisco": {
		DetectionPatterns: []string{"cisco", "ios", "nx-os", "asa", "catalyst", "nexus"},
		FingerprintOIDs: []OIDEntry{
			// Cisco-specific OIDs (highest priority)
			{"Cisco Software Version", "1.3.6.1.4.1.9.9.25.1.1.1.2.2", 1},
			{"Cisco Platform", "1.3.6.1.4.1.9.3.6.11.0", 1},
			{"Cisco IOS Version", "1.3.6.1.4.1.9.9.25.1.1.1.2.5", 1},
			// Entity MIB (lower priority for Cisco)
			{"Cisco Model", "1.3.6.1.2.1.47.1.1.1.1.13.1", 5},
			{"Cisco Serial Number", "1.3.6.1.2.1.47.1.1.1.1.11.1", 5},
			{"Cisco Hardware Version", "1.3.6.1.2.1.47.1.1.1.1.8.1", 5},
		},
	},
	"arista": {
		DetectionPatterns: []string{"arista", "eos"},
		FingerprintOIDs: []OIDEntry{
			// Arista-specific OIDs (highest priority)
			{"Arista EOS Version", "1.3.6.1.4.1.30065.3.1.1.0", 1},
			{"Arista EOS Build", "1.3.6.1.4.1.30065.3.1.2.0", 1},
			{"Arista Architecture", "1.3.6.1.4.1.30065.3.1.3.0", 1},
			{"Arista Internal Version", "1.3.6.1.4.1.30065.3.1.4.0", 1},
			// Entity MIB (but Arista-labeled for clarity)
			{"Arista Model", "1.3.6.1.2.1.47.1.1.1.1.13.1", 5},
			{"Arista Serial Number", "1.3.6.1.2.1.47.1.1.1.1.11.1", 5},
			{"Arista Hardware Revision", "1.3.6.1.2.1.47.1.1.1.1.8.1", 5},
		},
	},

	"aruba": {
		DetectionPatterns: []string{"aruba", "arubaos", "procurve", "hp", "jl", "jg", "jx", "cx", "instant"},
		FingerprintOIDs: []OIDEntry{
			// Working OIDs from your walk - PROVEN TO WORK
			{"HP Entity Module Description", "1.3.6.1.4.1.11.2.14.11.1.2.3.1.4.1", 1},
			{"HP Entity System Description", "1.3.6.1.4.1.11.2.14.11.1.2.4.1.4.1", 1},
			{"HP Entity Chassis Sensor", "1.3.6.1.4.1.11.2.14.11.1.2.6.1.7.1", 2},

			// Basic MIB-II that always works
			{"System Object ID", "1.3.6.1.2.1.1.2.0", 3},
			{"System Uptime", "1.3.6.1.2.1.1.3.0", 4},
			{"Interface Count", "1.3.6.1.2.1.2.1.0", 5},

			// Modern Aruba for future compatibility
			{"Aruba CX Model", "1.3.6.1.4.1.47196.4.1.1.3.8.2.1.1.1.4.1", 8},
			{"Aruba Wireless Model", "1.3.6.1.4.1.14823.2.2.1.1.1.2.0", 9},
		},
	},
	"dell": {
		DetectionPatterns: []string{"dell", "idrac", "powerconnect", "force10", "poweredge"},
		FingerprintOIDs: []OIDEntry{
			// Dell-specific OIDs (highest priority)
			{"Dell Chassis Service Tag", "1.3.6.1.4.1.674.10892.5.1.3.2.0", 1},
			{"Dell Chassis Model", "1.3.6.1.4.1.674.10892.5.1.3.12.0", 1},
			{"iDRAC Version", "1.3.6.1.4.1.674.10892.5.1.1.12.0", 1},
			{"Dell System BIOS Version", "1.3.6.1.4.1.674.10892.5.1.3.6.0", 2},
			{"Dell Management System Name", "1.3.6.1.4.1.674.10892.5.1.1.11.0", 2},
			{"iDRAC Product Name", "1.3.6.1.4.1.674.10892.5.1.1.1.0", 3},
			{"iDRAC URL", "1.3.6.1.4.1.674.10892.5.1.1.6.0", 3},
			{"iDRAC FQDN", "1.3.6.1.4.1.674.10892.5.1.1.15.0", 3},
			{"Global System Status", "1.3.6.1.4.1.674.10892.5.2.1.0", 4},
			{"System State Power Unit Status", "1.3.6.1.4.1.674.10892.5.2.4.0", 4},
			{"System State Temperature Status", "1.3.6.1.4.1.674.10892.5.2.3.0", 4},
			{"Power Supply Count", "1.3.6.1.4.1.674.10892.5.4.600.10.1.0", 5},
			{"Temperature Probe Count", "1.3.6.1.4.1.674.10892.5.4.700.10.1.0", 5},
		},
	},
	"fortinet": {
		DetectionPatterns: []string{"fortinet", "fortigate", "fortiswitch", "fortiap", "fortiwifi"},
		FingerprintOIDs: []OIDEntry{
			// Fortinet-specific OIDs (highest priority)
			{"Fortinet Model", "1.3.6.1.4.1.12356.101.1.2.1.0", 1},
			{"Fortinet Serial Number", "1.3.6.1.4.1.12356.101.1.2.2.0", 1},
			{"Fortinet Firmware Version", "1.3.6.1.4.1.12356.101.4.1.1.0", 1},
			{"Fortinet Hardware Version", "1.3.6.1.4.1.12356.101.1.2.3.0", 2},
			{"FortiGate HA Mode", "1.3.6.1.4.1.12356.101.13.1.1.0", 3},
			{"FortiGate CPU Usage", "1.3.6.1.4.1.12356.101.4.1.3.0", 4},
			{"FortiGate Memory Usage", "1.3.6.1.4.1.12356.101.4.1.4.0", 4},
			{"FortiGate Session Count", "1.3.6.1.4.1.12356.101.4.1.8.0", 5},
		},
	},
	"palo_alto": {
		DetectionPatterns: []string{"palo alto", "pan-os", "panorama"},
		FingerprintOIDs: []OIDEntry{
			// Palo Alto-specific OIDs (highest priority)
			{"PAN Model", "1.3.6.1.4.1.25461.2.1.2.1.1.0", 1},
			{"PAN Serial Number", "1.3.6.1.4.1.25461.2.1.2.1.3.0", 1},
			{"PAN-OS Version", "1.3.6.1.4.1.25461.2.1.2.1.2.0", 1},
			{"PAN HA State", "1.3.6.1.4.1.25461.2.1.2.1.11.0", 2},
		},
	},
	"apc": {
		DetectionPatterns: []string{"apc", "schneider", "powerware"},
		FingerprintOIDs: []OIDEntry{
			// APC-specific OIDs (highest priority)
			{"APC Model Number", "1.3.6.1.4.1.318.1.1.1.1.1.1.0", 1},
			{"APC Serial Number", "1.3.6.1.4.1.318.1.1.1.1.2.3.0", 1},
			{"APC Firmware Revision", "1.3.6.1.4.1.318.1.1.1.1.2.1.0", 1},
			{"APC Battery Status", "1.3.6.1.4.1.318.1.1.1.2.1.1.0", 2},
			{"APC Input Voltage", "1.3.6.1.4.1.318.1.1.1.3.2.1.0", 3},
		},
	},
}

// Generic fallback OIDs that work across multiple vendors
var GenericExtendedOIDs = []OIDEntry{
	{"Entity Model Name", "1.3.6.1.2.1.47.1.1.1.1.13.1", 1},
	{"Entity Serial Number", "1.3.6.1.2.1.47.1.1.1.1.11.1", 1},
	{"Entity Hardware Revision", "1.3.6.1.2.1.47.1.1.1.1.8.1", 2},
	{"Entity Software Revision", "1.3.6.1.2.1.47.1.1.1.1.10.1", 2},
	{"Entity Description", "1.3.6.1.2.1.47.1.1.1.1.2.1", 3},
}

func GetVendorOIDsWithDeviceType(vendor string, basicInfo map[string]string) []OIDEntry {
	if vendor != "aruba" {
		return GetVendorOIDs(vendor) // Use existing function for other vendors
	}

	// For Aruba, detect device type and filter OIDs accordingly
	sysDescr := basicInfo["sysDescr"]
	sysObjectID := basicInfo["sysObjectID"]
	deviceType := DetectArubaDeviceType(sysDescr, sysObjectID)

	allOIDs := VendorFingerprints["aruba"].FingerprintOIDs
	var filteredOIDs []OIDEntry

	switch deviceType {
	case "procurve":
		// For ProCurve switches, prioritize HP-specific OIDs
		for _, oid := range allOIDs {
			if strings.Contains(strings.ToLower(oid.Name), "hp") ||
				strings.Contains(strings.ToLower(oid.Name), "system") ||
				strings.Contains(strings.ToLower(oid.Name), "interface") {
				filteredOIDs = append(filteredOIDs, oid)
			}
		}
	case "aruba_cx":
		// For CX switches, prioritize CX-specific OIDs
		for _, oid := range allOIDs {
			if strings.Contains(strings.ToLower(oid.Name), "cx") ||
				strings.Contains(strings.ToLower(oid.Name), "system") ||
				strings.Contains(strings.ToLower(oid.Name), "entity") {
				filteredOIDs = append(filteredOIDs, oid)
			}
		}
	case "wireless":
		// For wireless devices, prioritize wireless OIDs
		for _, oid := range allOIDs {
			if strings.Contains(strings.ToLower(oid.Name), "wireless") ||
				strings.Contains(strings.ToLower(oid.Name), "arubaos") ||
				strings.Contains(strings.ToLower(oid.Name), "controller") ||
				strings.Contains(strings.ToLower(oid.Name), "system") {
				filteredOIDs = append(filteredOIDs, oid)
			}
		}
	default:
		// Unknown type - try a smaller set of most reliable OIDs
		for _, oid := range allOIDs {
			if oid.Priority <= 3 { // Only high-priority OIDs
				filteredOIDs = append(filteredOIDs, oid)
			}
		}
	}

	// Sort by priority
	for i := 0; i < len(filteredOIDs)-1; i++ {
		for j := 0; j < len(filteredOIDs)-i-1; j++ {
			if filteredOIDs[j].Priority > filteredOIDs[j+1].Priority {
				filteredOIDs[j], filteredOIDs[j+1] = filteredOIDs[j+1], filteredOIDs[j]
			}
		}
	}

	return filteredOIDs
}

// Enhanced VendorSpecificOIDPatterns
var VendorSpecificOIDPatterns = map[string][]string{
	"cisco":     {"1.3.6.1.4.1.9.", "cisco", "ios", "nx-os"},
	"arista":    {"1.3.6.1.4.1.30065.", "arista", "eos"},
	"dell":      {"1.3.6.1.4.1.674.", "dell", "idrac"},
	"fortinet":  {"1.3.6.1.4.1.12356.", "fortinet", "fortigate"},
	"palo_alto": {"1.3.6.1.4.1.25461.", "palo alto", "pan-os"},
	"apc":       {"1.3.6.1.4.1.318.", "apc"},
	"aruba": {"1.3.6.1.4.1.11.2.14.11.1.", "1.3.6.1.4.1.11.2.14.11.5.", "1.3.6.1.4.1.47196.", "1.3.6.1.4.1.14823.",
		"aruba", "procurve", "hp", "arubaos", "cx", "instant", "wireless"},
}

// DetectVendorFromSysDescr detects vendor based on system description
func DetectVendorFromSysDescr(sysDescr string) string {
	if sysDescr == "" {
		return "unknown"
	}

	sysDescrLower := strings.ToLower(sysDescr)

	for vendor, config := range VendorFingerprints {
		for _, pattern := range config.DetectionPatterns {
			if strings.Contains(sysDescrLower, strings.ToLower(pattern)) {
				return vendor
			}
		}
	}

	return "unknown"
}

// DetectVendorFromOIDData attempts to detect vendor from collected OID data
func DetectVendorFromOIDData(fingerprintData map[string]string) string {
	vendorScores := make(map[string]int)

	for fieldName, value := range fingerprintData {
		fieldLower := strings.ToLower(fieldName)
		valueLower := strings.ToLower(value)

		// Score based on field names and values
		for vendor, patterns := range VendorSpecificOIDPatterns {
			for _, pattern := range patterns {
				patternLower := strings.ToLower(pattern)

				// Check field name
				if strings.Contains(fieldLower, patternLower) {
					vendorScores[vendor] += 10
				}

				// Check value content
				if strings.Contains(valueLower, patternLower) {
					vendorScores[vendor] += 5
				}
			}
		}

		// Special scoring for specific field patterns
		if strings.Contains(fieldLower, "arista") && strings.Contains(valueLower, "eos") {
			vendorScores["arista"] += 20
		}
		if strings.Contains(fieldLower, "cisco") && (strings.Contains(valueLower, "ios") || strings.Contains(valueLower, "nx-os")) {
			vendorScores["cisco"] += 20
		}
		if strings.Contains(fieldLower, "dell") && strings.Contains(valueLower, "idrac") {
			vendorScores["dell"] += 20
		}
	}

	// Find highest scoring vendor
	maxScore := 0
	detectedVendor := "unknown"

	for vendor, score := range vendorScores {
		if score > maxScore {
			maxScore = score
			detectedVendor = vendor
		}
	}

	// Require minimum score to avoid false positives
	if maxScore < 5 {
		return "unknown"
	}

	return detectedVendor
}

// DetectVendorFromContact detects vendor based on system contact
func DetectVendorFromContact(sysContact string) string {
	if sysContact == "" {
		return "unknown"
	}

	contactLower := strings.ToLower(sysContact)

	// Vendor-specific contact patterns
	contactPatterns := map[string][]string{
		"dell":      {"dell.com", "support@dell.com", "dell inc", "dell technologies"},
		"cisco":     {"cisco.com", "cisco systems", "support@cisco.com", "cisco inc"},
		"arista":    {"arista.com", "arista networks", "support@arista.com"},
		"palo_alto": {"paloaltonetworks.com", "support@paloaltonetworks.com", "palo alto networks"},
		"aruba":     {"arubanetworks.com", "support@arubanetworks.com", "aruba networks", "hpe.com"},
		"apc":       {"apc.com", "schneider-electric.com", "support@apc.com", "schneider electric"},
		"fortinet":  {"fortinet.com", "support@fortinet.com", "fortinet inc"},
	}

	for vendor, patterns := range contactPatterns {
		for _, pattern := range patterns {
			if strings.Contains(contactLower, pattern) {
				return vendor
			}
		}
	}

	return "unknown"
}

// DetectVendorComprehensive performs comprehensive vendor detection
func DetectVendorComprehensive(sysDescr, sysContact, sysName, sysLocation string) (vendor, confidence, method string) {
	// First try sysDescr (most reliable when present)
	if sysDescr != "" {
		vendor := DetectVendorFromSysDescr(sysDescr)
		if vendor != "unknown" {
			return vendor, "high", "sysDescr"
		}
	}

	// Then try sysContact (good for BMCs like iDRAC)
	if sysContact != "" {
		vendor := DetectVendorFromContact(sysContact)
		if vendor != "unknown" {
			return vendor, "medium", "sysContact"
		}
	}

	// Try sysName for hostname patterns
	if sysName != "" {
		nameLower := strings.ToLower(sysName)
		namePatterns := map[string][]string{
			"dell":      {"idrac", "dell"},
			"cisco":     {"cisco", "switch", "router"},
			"arista":    {"arista", "eos"},
			"palo_alto": {"pa-", "panorama"},
			"aruba":     {"aruba", "procurve"},
			"fortinet":  {"fortigate", "fortinet"},
		}

		for vendor, patterns := range namePatterns {
			for _, pattern := range patterns {
				if strings.Contains(nameLower, pattern) {
					return vendor, "low", "sysName"
				}
			}
		}
	}

	// Finally try sysLocation for any vendor hints
	if sysLocation != "" {
		locationLower := strings.ToLower(sysLocation)
		for vendor, config := range VendorFingerprints {
			for _, pattern := range config.DetectionPatterns {
				if strings.Contains(locationLower, strings.ToLower(pattern)) {
					return vendor, "low", "sysLocation"
				}
			}
		}
	}

	return "unknown", "none", "no_detection"
}

// GetVendorOIDs returns OIDs for specific vendor, sorted by priority
func GetVendorOIDs(vendor string) []OIDEntry {
	if vendorFingerprint, exists := VendorFingerprints[vendor]; exists {
		// Sort by priority (lower number = higher priority)
		oids := make([]OIDEntry, len(vendorFingerprint.FingerprintOIDs))
		copy(oids, vendorFingerprint.FingerprintOIDs)

		// Simple bubble sort by priority
		for i := 0; i < len(oids)-1; i++ {
			for j := 0; j < len(oids)-i-1; j++ {
				if oids[j].Priority > oids[j+1].Priority {
					oids[j], oids[j+1] = oids[j+1], oids[j]
				}
			}
		}

		return oids
	}
	return GenericExtendedOIDs
}

// GetVendorPriorityOIDs returns priority OIDs for specific vendor (most reliable ones first)
func GetVendorPriorityOIDs(vendor string, maxOIDs int) []OIDEntry {
	allOIDs := GetVendorOIDs(vendor)

	if maxOIDs > len(allOIDs) {
		maxOIDs = len(allOIDs)
	}

	return allOIDs[:maxOIDs]
}

// IsValidSNMPValue checks if SNMP value is valid and useful
func IsValidSNMPValue(value string) bool {
	if value == "" {
		return false
	}

	// Clean up common unwanted values
	unwantedValues := []string{
		"No Such Object currently exists at this OID",
		"No Such Instance currently exists at this OID",
		"End of MIB",
		"NULL",
		"None",
		"\"\"",
	}

	for _, unwanted := range unwantedValues {
		if value == unwanted || strings.ToLower(value) == strings.ToLower(unwanted) {
			return false
		}
	}

	return true
}

// ExtractImportantFields extracts the most important fields from fingerprint data
func ExtractImportantFields(fingerprintData map[string]string) map[string]string {
	importantFields := make(map[string]string)

	// Define important field patterns
	importantPatterns := map[string][]string{
		"model":   {"model", "chassis model", "product"},
		"serial":  {"serial", "service tag"},
		"version": {"version", "firmware", "software", "bios"},
		"vendor":  {"vendor", "manufacturer"},
	}

	for category, patterns := range importantPatterns {
		for fieldName, value := range fingerprintData {
			fieldLower := strings.ToLower(fieldName)

			for _, pattern := range patterns {
				if strings.Contains(fieldLower, pattern) {
					importantFields[category] = value
					goto nextCategory // Break out of both loops for this category
				}
			}
		}
	nextCategory:
	}

	return importantFields
}

// FormatFingerprintSummary formats fingerprint result into a readable summary
func FormatFingerprintSummary(result *FingerprintResult) string {
	var lines []string

	lines = append(lines, fmt.Sprintf("Vendor: %s", result.DetectedVendor))
	lines = append(lines, fmt.Sprintf("Confidence: %s", result.Confidence))
	lines = append(lines, fmt.Sprintf("Detection Method: %s", result.DetectionMethod))
	lines = append(lines, fmt.Sprintf("Scan Duration: %v", result.ScanDuration))
	lines = append(lines, fmt.Sprintf("Fields Found: %d", len(result.FingerprintData)))

	if len(result.FingerprintData) > 0 {
		important := ExtractImportantFields(result.FingerprintData)
		if len(important) > 0 {
			lines = append(lines, "Key Information:")
			for category, value := range important {
				lines = append(lines, fmt.Sprintf("  %s: %s", strings.Title(category), value))
			}
		}
	}

	if result.ErrorMessage != "" {
		lines = append(lines, fmt.Sprintf("Error: %s", result.ErrorMessage))
	}

	return strings.Join(lines, "\n")
}

// IsVendorDetected checks if vendor detection was successful
func IsVendorDetected(result *FingerprintResult) bool {
	return result.Success && result.DetectedVendor != "unknown" && result.Confidence != "none"
}

// HasVendorData checks if vendor-specific data was collected
func HasVendorData(result *FingerprintResult) bool {
	return len(result.FingerprintData) > 0
}

func DetectArubaDeviceType(sysDescr string, sysObjectID string) string {
	if sysDescr == "" && sysObjectID == "" {
		return "unknown"
	}

	sysDescrLower := strings.ToLower(sysDescr)

	// ProCurve/Classic HP Switch patterns
	if strings.Contains(sysDescrLower, "procurve") ||
		strings.Contains(sysDescrLower, "jl") ||
		strings.Contains(sysDescrLower, "jg") ||
		strings.Contains(sysDescrLower, "2540") ||
		strings.Contains(sysDescrLower, "2930") ||
		strings.Contains(sysDescrLower, "2920") ||
		strings.Contains(sysDescrLower, "5400") {
		return "procurve"
	}

	// Modern Aruba CX patterns
	if strings.Contains(sysDescrLower, "aruba cx") ||
		strings.Contains(sysDescrLower, "6xxx") ||
		strings.Contains(sysDescrLower, "8xxx") {
		return "aruba_cx"
	}

	// Wireless patterns
	if strings.Contains(sysDescrLower, "wireless") ||
		strings.Contains(sysDescrLower, "controller") ||
		strings.Contains(sysDescrLower, "ap") ||
		strings.Contains(sysDescrLower, "arubaos") {
		return "wireless"
	}

	// Check sysObjectID for device type
	if sysObjectID != "" {
		// HP ProCurve OID patterns
		if strings.HasPrefix(sysObjectID, "1.3.6.1.4.1.11.2.3.7.11") {
			return "procurve"
		}
		// Aruba CX OID patterns
		if strings.HasPrefix(sysObjectID, "1.3.6.1.4.1.47196") {
			return "aruba_cx"
		}
		// Aruba Wireless OID patterns
		if strings.HasPrefix(sysObjectID, "1.3.6.1.4.1.14823") {
			return "wireless"
		}
	}

	return "unknown"
}
