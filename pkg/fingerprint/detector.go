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

var GlobalConfigManager *ConfigManager

// These will be populated by the YAML config loader
var (
	CommonOIDs                map[string]string
	VendorFingerprints        map[string]VendorFingerprint
	VendorSpecificOIDPatterns map[string][]string
	GenericExtendedOIDs       []OIDEntry
)

// Initialize with empty maps - will be populated by config loader
func init() {
	CommonOIDs = make(map[string]string)
	VendorFingerprints = make(map[string]VendorFingerprint)
	VendorSpecificOIDPatterns = make(map[string][]string)
	GenericExtendedOIDs = []OIDEntry{}
}

// DetectVendorFromSysDescr detects vendor based on system description
// Uses YAML-loaded detection patterns with proper priority enforcement
// Add this debug code to DetectVendorFromSysDescr function
func DetectVendorFromSysDescr(sysDescr string) string {
	if sysDescr == "" {
		return "unknown"
	}

	sysDescrLower := strings.ToLower(sysDescr)

	// DEBUG: Log what we're analyzing
	fmt.Printf("=== DEBUG DetectVendorFromSysDescr ===\n")
	fmt.Printf("Input sysDescr: %s\n", sysDescr)
	fmt.Printf("Lower case: %s\n", sysDescrLower)

	// Use priority order from config if available
	if GlobalConfigManager != nil && GlobalConfigManager.GetConfig() != nil {
		config := GlobalConfigManager.GetConfig()

		fmt.Printf("Using YAML config with %d vendors in priority order\n", len(config.DetectionRules.PriorityOrder))

		var bestMatch string
		var bestPriority int = len(config.DetectionRules.PriorityOrder) + 1

		for priority, vendorKey := range config.DetectionRules.PriorityOrder {
			vendorConfig, exists := VendorFingerprints[vendorKey]
			if !exists {
				continue
			}

			// Check if this vendor matches
			matched := false
			matchedPattern := ""
			for _, pattern := range vendorConfig.DetectionPatterns {
				if strings.Contains(sysDescrLower, strings.ToLower(pattern)) {
					matched = true
					matchedPattern = pattern
					break
				}
			}

			if !matched {
				fmt.Printf("  %s (priority %d): NO MATCH\n", vendorKey, priority)
				continue
			}

			fmt.Printf("  %s (priority %d): MATCHED pattern '%s'\n", vendorKey, priority, matchedPattern)

			// Check exclusion patterns
			if yamlVendor, yamlExists := config.Vendors[vendorKey]; yamlExists {
				excluded := false
				excludedBy := ""
				for _, exclusion := range yamlVendor.ExclusionPatterns {
					if strings.Contains(sysDescrLower, strings.ToLower(exclusion)) {
						excluded = true
						excludedBy = exclusion
						break
					}
				}

				if excluded {
					fmt.Printf("    -> EXCLUDED by pattern '%s'\n", excludedBy)
				} else {
					fmt.Printf("    -> NOT EXCLUDED, checking priority\n")
					if priority < bestPriority {
						fmt.Printf("    -> NEW BEST MATCH (priority %d < %d)\n", priority, bestPriority)
						bestMatch = vendorKey
						bestPriority = priority
					} else {
						fmt.Printf("    -> Lower priority than current best (%d >= %d)\n", priority, bestPriority)
					}
				}
			} else {
				// Legacy vendor - take it if higher priority
				if priority < bestPriority {
					fmt.Printf("    -> Legacy vendor, NEW BEST MATCH\n")
					bestMatch = vendorKey
					bestPriority = priority
				}
			}
		}

		fmt.Printf("Final result: %s\n", bestMatch)
		fmt.Printf("=====================================\n")

		if bestMatch != "" {
			return bestMatch
		}
	} else {
		fmt.Printf("No YAML config available, using fallback\n")
		// Fallback to basic pattern matching if no YAML config
		for vendor, config := range VendorFingerprints {
			for _, pattern := range config.DetectionPatterns {
				if strings.Contains(sysDescrLower, strings.ToLower(pattern)) {
					fmt.Printf("Fallback matched: %s with pattern %s\n", vendor, pattern)
					return vendor
				}
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

// GetConfiguredVendors returns list of vendors from config
func GetConfiguredVendors() []string {
	if GlobalConfigManager != nil && GlobalConfigManager.GetConfig() != nil {
		vendors := make([]string, 0, len(GlobalConfigManager.GetConfig().Vendors))
		for vendor := range GlobalConfigManager.GetConfig().Vendors {
			vendors = append(vendors, vendor)
		}
		return vendors
	}

	// Fallback to hardcoded
	vendors := make([]string, 0, len(VendorFingerprints))
	for vendor := range VendorFingerprints {
		vendors = append(vendors, vendor)
	}
	return vendors
}

// DetectVendorFromContact detects vendor based on system contact
// Now uses priority-based detection like DetectVendorFromSysDescr
func DetectVendorFromContact(sysContact string) string {
	if sysContact == "" {
		return "unknown"
	}

	contactLower := strings.ToLower(sysContact)

	// Use priority order from config if available
	if GlobalConfigManager != nil && GlobalConfigManager.GetConfig() != nil {
		config := GlobalConfigManager.GetConfig()

		var bestMatch string
		var bestPriority int = len(config.DetectionRules.PriorityOrder) + 1

		for priority, vendorKey := range config.DetectionRules.PriorityOrder {
			vendorConfig, exists := VendorFingerprints[vendorKey]
			if !exists {
				continue
			}

			// Check if this vendor matches
			matched := false
			for _, pattern := range vendorConfig.DetectionPatterns {
				if strings.Contains(contactLower, strings.ToLower(pattern)) {
					matched = true
					break
				}
			}

			if !matched {
				continue
			}

			// Check exclusion patterns
			if yamlVendor, yamlExists := config.Vendors[vendorKey]; yamlExists {
				excluded := false
				for _, exclusion := range yamlVendor.ExclusionPatterns {
					if strings.Contains(contactLower, strings.ToLower(exclusion)) {
						excluded = true
						break
					}
				}

				if !excluded && priority < bestPriority {
					bestMatch = vendorKey
					bestPriority = priority
				}
			} else {
				if priority < bestPriority {
					bestMatch = vendorKey
					bestPriority = priority
				}
			}
		}

		if bestMatch != "" {
			return bestMatch
		}
	} else {
		// Fallback to pattern matching
		for vendor, patterns := range VendorSpecificOIDPatterns {
			for _, pattern := range patterns {
				if strings.Contains(contactLower, strings.ToLower(pattern)) {
					return vendor
				}
			}
		}
	}

	return "unknown"
}

// DetectVendorComprehensive performs comprehensive vendor detection
func DetectVendorComprehensive(sysDescr, sysContact, sysName, sysLocation string) (vendor, confidence, method string) {
	// Use YAML config if available
	if GlobalConfigManager != nil && GlobalConfigManager.GetConfig() != nil {
		return GlobalConfigManager.DetectVendorFromConfig(sysDescr, sysContact, sysName, sysLocation)
	}

	// Fallback to legacy detection
	// First try sysDescr (most reliable when present)
	if sysDescr != "" {
		vendor := DetectVendorFromSysDescr(sysDescr)
		if vendor != "unknown" {
			return vendor, "high", "sysDescr"
		}
	}

	// Then try sysContact
	if sysContact != "" {
		vendor := DetectVendorFromContact(sysContact)
		if vendor != "unknown" {
			return vendor, "medium", "sysContact"
		}
	}

	// Try sysName for hostname patterns
	if sysName != "" {
		vendor := DetectVendorFromSysDescr(sysName) // Reuse pattern matching
		if vendor != "unknown" {
			return vendor, "low", "sysName"
		}
	}

	// Finally try sysLocation
	if sysLocation != "" {
		vendor := DetectVendorFromSysDescr(sysLocation) // Reuse pattern matching
		if vendor != "unknown" {
			return vendor, "low", "sysLocation"
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

// GetVendorOIDsWithDeviceType returns OIDs filtered by device type (uses YAML config if available)
func GetVendorOIDsWithDeviceType(vendor string, basicInfo map[string]string) []OIDEntry {
	// Use YAML config if available
	if GlobalConfigManager != nil && GlobalConfigManager.GetConfig() != nil {
		sysDescr := basicInfo["sysDescr"]
		sysObjectID := basicInfo["sysObjectID"]
		deviceType := DetectDeviceType(vendor, sysDescr, sysObjectID)
		return GlobalConfigManager.GetVendorOIDsForDeviceType(vendor, deviceType)
	}

	// Fallback to legacy behavior for Aruba
	if vendor == "aruba" {
		sysDescr := basicInfo["sysDescr"]
		sysObjectID := basicInfo["sysObjectID"]
		deviceType := DetectArubaDeviceType(sysDescr, sysObjectID)

		allOIDs := GetVendorOIDs(vendor)
		var filteredOIDs []OIDEntry

		switch deviceType {
		case "procurve":
			for _, oid := range allOIDs {
				if strings.Contains(strings.ToLower(oid.Name), "hp") ||
					strings.Contains(strings.ToLower(oid.Name), "system") ||
					strings.Contains(strings.ToLower(oid.Name), "interface") {
					filteredOIDs = append(filteredOIDs, oid)
				}
			}
		default:
			filteredOIDs = allOIDs
		}

		return filteredOIDs
	}

	return GetVendorOIDs(vendor)
}

// GetVendorPriorityOIDs returns priority OIDs for specific vendor (most reliable ones first)
func GetVendorPriorityOIDs(vendor string, maxOIDs int) []OIDEntry {
	allOIDs := GetVendorOIDs(vendor)

	if maxOIDs > len(allOIDs) {
		maxOIDs = len(allOIDs)
	}

	return allOIDs[:maxOIDs]
}

// DetectDeviceType detects device type for a vendor
func DetectDeviceType(vendor, sysDescr, sysObjectID string) string {
	switch vendor {
	case "aruba":
		return DetectArubaDeviceType(sysDescr, sysObjectID)
	case "hp_printer":
		return "printer"
	case "dell":
		return "server"
	case "cisco":
		if strings.Contains(strings.ToLower(sysDescr), "switch") {
			return "switch"
		}
		if strings.Contains(strings.ToLower(sysDescr), "router") {
			return "router"
		}
		return "network"
	default:
		return "unknown"
	}
}

// DetectArubaDeviceType detects specific Aruba device types
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
		if strings.HasPrefix(sysObjectID, "1.3.6.1.4.1.11.2.3.7.11") {
			return "procurve"
		}
		if strings.HasPrefix(sysObjectID, "1.3.6.1.4.1.47196") {
			return "aruba_cx"
		}
		if strings.HasPrefix(sysObjectID, "1.3.6.1.4.1.14823") {
			return "wireless"
		}
	}

	return "unknown"
}

// IsValidSNMPValue checks if SNMP value is valid and useful
func IsValidSNMPValue(value string) bool {
	if value == "" {
		return false
	}

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
					goto nextCategory
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

// GetSupportedVendors returns a list of supported vendors
func GetSupportedVendors() []string {
	// Use YAML config if available
	if GlobalConfigManager != nil && GlobalConfigManager.GetConfig() != nil {
		return GetConfiguredVendors()
	}

	// Fallback to hardcoded list
	vendors := make([]string, 0, len(VendorFingerprints))
	for vendor := range VendorFingerprints {
		vendors = append(vendors, vendor)
	}
	return vendors
}
