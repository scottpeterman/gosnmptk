package fingerprint

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// YAMLConfig represents the complete YAML configuration structure
type YAMLConfig struct {
	Version  string `yaml:"version"`
	Metadata struct {
		Description  string   `yaml:"description"`
		LastUpdated  string   `yaml:"last_updated"`
		Contributors []string `yaml:"contributors"`
	} `yaml:"metadata"`
	CommonOIDs     map[string]string           `yaml:"common_oids"`
	GenericOIDs    []YAMLOIDEntry              `yaml:"generic_oids"`
	Vendors        map[string]YAMLVendorConfig `yaml:"vendors"`
	DetectionRules struct {
		PriorityOrder    []string          `yaml:"priority_order"`
		ConfidenceLevels map[string]string `yaml:"confidence_levels"`
	} `yaml:"detection_rules"`
	Scanning struct {
		DefaultTimeout       int  `yaml:"default_timeout"`
		OIDQueryTimeout      int  `yaml:"oid_query_timeout"`
		DelayBetweenQueries  int  `yaml:"delay_between_queries"`
		MaxConcurrentQueries int  `yaml:"max_concurrent_queries"`
		RetryFailedOIDs      bool `yaml:"retry_failed_oids"`
		RetryCount           int  `yaml:"retry_count"`
	} `yaml:"scanning"`
}

// YAMLVendorConfig represents a vendor configuration in YAML
type YAMLVendorConfig struct {
	DisplayName       string         `yaml:"display_name"`
	EnterpriseOID     string         `yaml:"enterprise_oid"`
	DetectionPatterns []string       `yaml:"detection_patterns"`
	OIDPatterns       []string       `yaml:"oid_patterns"`
	DeviceTypes       []string       `yaml:"device_types"`
	ExclusionPatterns []string       `yaml:"exclusion_patterns,omitempty"`
	FingerprintOIDs   []YAMLOIDEntry `yaml:"fingerprint_oids"`
}

// YAMLOIDEntry represents an OID entry in YAML
type YAMLOIDEntry struct {
	Name        string   `yaml:"name"`
	OID         string   `yaml:"oid"`
	Priority    int      `yaml:"priority"`
	Description string   `yaml:"description"`
	DeviceTypes []string `yaml:"device_types,omitempty"`
}

// ConfigManager manages the YAML configuration
type ConfigManager struct {
	config     *YAMLConfig
	configPath string
	lastLoaded time.Time
}

// NewConfigManager creates a new configuration manager
func NewConfigManager(configPath string) *ConfigManager {
	return &ConfigManager{
		configPath: configPath,
	}
}

// Add this debug version to your LoadConfig method in config.go
func (cm *ConfigManager) LoadConfig() error {
	fmt.Printf("=== DEBUG LoadConfig ===\n")

	// Try multiple possible config locations
	possiblePaths := []string{
		cm.configPath,
		"vendor_fingerprints.yaml",
		"config/vendor_fingerprints.yaml",
		"/etc/snmp-fingerprint/vendor_fingerprints.yaml",
		filepath.Join(os.Getenv("HOME"), ".snmp-fingerprint", "vendor_fingerprints.yaml"),
	}

	var configData []byte
	var err error
	var usedPath string

	fmt.Printf("Trying to load config from these paths:\n")
	for _, path := range possiblePaths {
		if path == "" {
			continue
		}

		fmt.Printf("  Trying: %s\n", path)
		configData, err = ioutil.ReadFile(path)
		if err == nil {
			usedPath = path
			fmt.Printf("  SUCCESS: Loaded from %s\n", path)
			break
		} else {
			fmt.Printf("  FAILED: %v\n", err)
		}
	}

	if err != nil {
		fmt.Printf("ERROR: Failed to read config file from any location: %v\n", err)
		return fmt.Errorf("failed to read config file from any location: %w", err)
	}

	fmt.Printf("Config file size: %d bytes\n", len(configData))
	fmt.Printf("First 200 chars: %s\n", string(configData[:min(200, len(configData))]))

	var config YAMLConfig
	if err := yaml.Unmarshal(configData, &config); err != nil {
		fmt.Printf("ERROR: Failed to parse YAML config: %v\n", err)
		return fmt.Errorf("failed to parse YAML config: %w", err)
	}

	fmt.Printf("Parsed config successfully!\n")
	fmt.Printf("Version: %s\n", config.Version)
	fmt.Printf("Number of vendors: %d\n", len(config.Vendors))
	fmt.Printf("Priority order length: %d\n", len(config.DetectionRules.PriorityOrder))
	fmt.Printf("Priority order: %v\n", config.DetectionRules.PriorityOrder)

	cm.config = &config
	cm.configPath = usedPath
	cm.lastLoaded = time.Now()

	fmt.Printf("Config loaded successfully from: %s\n", usedPath)
	fmt.Printf("========================\n")
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// GetConfig returns the loaded configuration
func (cm *ConfigManager) GetConfig() *YAMLConfig {
	return cm.config
}

// ReloadIfChanged reloads the config if the file has been modified
func (cm *ConfigManager) ReloadIfChanged() error {
	if cm.configPath == "" {
		return nil
	}

	stat, err := os.Stat(cm.configPath)
	if err != nil {
		return err
	}

	if stat.ModTime().After(cm.lastLoaded) {
		return cm.LoadConfig()
	}

	return nil
}

// ConvertToLegacyFormat converts YAML config to legacy format for compatibility
func (cm *ConfigManager) ConvertToLegacyFormat() error {
	if cm.config == nil {
		return fmt.Errorf("no configuration loaded")
	}
	// ADD THIS DEBUG
	fmt.Printf("=== DEBUG ConvertToLegacyFormat ===\n")
	fmt.Printf("YAML Priority Order: %v\n", cm.config.DetectionRules.PriorityOrder)
	fmt.Printf("YAML Priority Order Length: %d\n", len(cm.config.DetectionRules.PriorityOrder))
	if len(cm.config.DetectionRules.PriorityOrder) > 0 {
		fmt.Printf("First 3 from YAML: %v\n", cm.config.DetectionRules.PriorityOrder[:3])
	}
	fmt.Printf("================================\n")

	// Clear existing legacy data
	VendorFingerprints = make(map[string]VendorFingerprint)
	VendorSpecificOIDPatterns = make(map[string][]string)
	CommonOIDs = make(map[string]string)

	// Convert common OIDs
	for name, oid := range cm.config.CommonOIDs {
		CommonOIDs[name] = oid
	}

	// Convert vendor configurations
	for vendorKey, vendorConfig := range cm.config.Vendors {
		// Convert OID entries
		var oidEntries []OIDEntry
		for _, yamlOID := range vendorConfig.FingerprintOIDs {
			oidEntries = append(oidEntries, OIDEntry{
				Name:     yamlOID.Name,
				OID:      yamlOID.OID,
				Priority: yamlOID.Priority,
			})
		}

		// Sort by priority
		sort.Slice(oidEntries, func(i, j int) bool {
			return oidEntries[i].Priority < oidEntries[j].Priority
		})

		VendorFingerprints[vendorKey] = VendorFingerprint{
			DetectionPatterns: vendorConfig.DetectionPatterns,
			FingerprintOIDs:   oidEntries,
		}

		VendorSpecificOIDPatterns[vendorKey] = vendorConfig.OIDPatterns
	}

	// Convert generic OIDs
	GenericExtendedOIDs = nil
	for _, yamlOID := range cm.config.GenericOIDs {
		GenericExtendedOIDs = append(GenericExtendedOIDs, OIDEntry{
			Name:     yamlOID.Name,
			OID:      yamlOID.OID,
			Priority: yamlOID.Priority,
		})
	}

	sort.Slice(GenericExtendedOIDs, func(i, j int) bool {
		return GenericExtendedOIDs[i].Priority < GenericExtendedOIDs[j].Priority
	})

	return nil
}

// GetVendorConfig returns configuration for a specific vendor
func (cm *ConfigManager) GetVendorConfig(vendor string) (*YAMLVendorConfig, bool) {
	if cm.config == nil {
		return nil, false
	}

	config, exists := cm.config.Vendors[vendor]
	return &config, exists
}

// GetVendorOIDsForDeviceType returns OIDs filtered by device type
func (cm *ConfigManager) GetVendorOIDsForDeviceType(vendor string, deviceType string) []OIDEntry {
	vendorConfig, exists := cm.GetVendorConfig(vendor)
	if !exists {
		return GetVendorOIDs(vendor) // Fallback to legacy
	}

	var filteredOIDs []OIDEntry
	for _, yamlOID := range vendorConfig.FingerprintOIDs {
		// If no device types specified, include OID
		if len(yamlOID.DeviceTypes) == 0 {
			filteredOIDs = append(filteredOIDs, OIDEntry{
				Name:     yamlOID.Name,
				OID:      yamlOID.OID,
				Priority: yamlOID.Priority,
			})
			continue
		}

		// Check if this OID applies to the device type
		for _, dt := range yamlOID.DeviceTypes {
			if strings.EqualFold(dt, deviceType) {
				filteredOIDs = append(filteredOIDs, OIDEntry{
					Name:     yamlOID.Name,
					OID:      yamlOID.OID,
					Priority: yamlOID.Priority,
				})
				break
			}
		}
	}

	// Sort by priority
	sort.Slice(filteredOIDs, func(i, j int) bool {
		return filteredOIDs[i].Priority < filteredOIDs[j].Priority
	})

	return filteredOIDs
}

// DetectVendorFromConfig uses YAML config for vendor detection with proper priority
func (cm *ConfigManager) DetectVendorFromConfig(sysDescr, sysContact, sysName, sysLocation string) (vendor, confidence, method string) {
	if cm.config == nil {
		return DetectVendorComprehensive(sysDescr, sysContact, sysName, sysLocation) // Fallback
	}

	// DEBUG: Add logging to see what's happening
	fmt.Printf("=== DEBUG DetectVendorFromConfig ===\n")
	fmt.Printf("sysDescr: %s\n", sysDescr)
	fmt.Printf("Priority order: %v\n", cm.config.DetectionRules.PriorityOrder)

	// Check each field in order of reliability: sysDescr > sysContact > sysName > sysLocation
	testFields := []struct {
		name  string
		value string
		conf  string
	}{
		{"sysDescr", sysDescr, "high"},
		{"sysContact", sysContact, "medium"},
		{"sysName", sysName, "low"},
		{"sysLocation", sysLocation, "low"},
	}

	for _, field := range testFields {
		if field.value == "" {
			continue
		}

		fmt.Printf("\nTesting field %s: %s\n", field.name, field.value)

		// Use priority order from config with proper priority tracking
		var bestMatch string
		var bestPriority int = len(cm.config.DetectionRules.PriorityOrder) + 1

		for priority, vendorKey := range cm.config.DetectionRules.PriorityOrder {
			vendorConfig, exists := cm.config.Vendors[vendorKey]
			if !exists {
				continue
			}

			// Check if this vendor matches detection patterns
			matched := cm.matchesDetectionPatterns(field.value, vendorConfig.DetectionPatterns)
			if !matched {
				fmt.Printf("  %s (priority %d): NO MATCH\n", vendorKey, priority)
				continue
			}

			fmt.Printf("  %s (priority %d): MATCHED\n", vendorKey, priority)

			// Check exclusion patterns
			excluded := cm.matchesExclusionPatterns(field.value, vendorConfig.ExclusionPatterns)
			if excluded {
				fmt.Printf("    -> EXCLUDED\n")
				continue
			}

			fmt.Printf("    -> NOT EXCLUDED\n")

			// Update best match if higher priority
			if priority < bestPriority {
				fmt.Printf("    -> NEW BEST MATCH (priority %d)\n", priority)
				bestMatch = vendorKey
				bestPriority = priority
			} else {
				fmt.Printf("    -> Lower priority than current best\n")
			}
		}

		if bestMatch != "" {
			fmt.Printf("Final result for %s: %s\n", field.name, bestMatch)
			fmt.Printf("=====================================\n")
			return bestMatch, field.conf, field.name
		}
	}

	fmt.Printf("No vendor detected\n")
	fmt.Printf("=====================================\n")
	return "unknown", "none", "no_detection"
}

// Helper function to check detection patterns
func (cm *ConfigManager) matchesDetectionPatterns(text string, patterns []string) bool {
	textLower := strings.ToLower(text)
	for _, pattern := range patterns {
		if strings.Contains(textLower, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

// Helper function to check exclusion patterns
func (cm *ConfigManager) matchesExclusionPatterns(text string, patterns []string) bool {
	textLower := strings.ToLower(text)
	for _, pattern := range patterns {
		if strings.Contains(textLower, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

// matchesPatterns checks if text matches detection patterns but not exclusion patterns
func (cm *ConfigManager) matchesPatterns(text string, detectionPatterns, exclusionPatterns []string) bool {
	textLower := strings.ToLower(text)

	// First check exclusion patterns
	for _, exclusion := range exclusionPatterns {
		if strings.Contains(textLower, strings.ToLower(exclusion)) {
			return false
		}
	}

	// Then check detection patterns
	for _, pattern := range detectionPatterns {
		if strings.Contains(textLower, strings.ToLower(pattern)) {
			return true
		}
	}

	return false
}

// GetScanningConfig returns scanning configuration
func (cm *ConfigManager) GetScanningConfig() (timeout time.Duration, oidTimeout time.Duration, delay time.Duration) {
	if cm.config == nil {
		return 30 * time.Second, 10 * time.Second, 100 * time.Millisecond // Defaults
	}

	return time.Duration(cm.config.Scanning.DefaultTimeout) * time.Second,
		time.Duration(cm.config.Scanning.OIDQueryTimeout) * time.Second,
		time.Duration(cm.config.Scanning.DelayBetweenQueries) * time.Millisecond
}

// ValidateConfig validates the loaded configuration
func (cm *ConfigManager) ValidateConfig() error {
	if cm.config == nil {
		return fmt.Errorf("no configuration loaded")
	}

	// Check for required fields
	if cm.config.Version == "" {
		return fmt.Errorf("config version is required")
	}

	if len(cm.config.Vendors) == 0 {
		return fmt.Errorf("at least one vendor must be configured")
	}

	// Validate each vendor
	for vendorKey, vendor := range cm.config.Vendors {
		if vendor.DisplayName == "" {
			return fmt.Errorf("vendor %s missing display_name", vendorKey)
		}

		if len(vendor.DetectionPatterns) == 0 {
			return fmt.Errorf("vendor %s has no detection patterns", vendorKey)
		}

		if len(vendor.FingerprintOIDs) == 0 {
			return fmt.Errorf("vendor %s has no fingerprint OIDs", vendorKey)
		}

		// Validate OIDs
		for _, oid := range vendor.FingerprintOIDs {
			if oid.Name == "" || oid.OID == "" {
				return fmt.Errorf("vendor %s has invalid OID entry", vendorKey)
			}
		}
	}

	return nil
}

// SaveConfig saves the current configuration to YAML file
func (cm *ConfigManager) SaveConfig(path string) error {
	if cm.config == nil {
		return fmt.Errorf("no configuration to save")
	}

	data, err := yaml.Marshal(cm.config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := ioutil.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// InitializeFromYAML initializes the fingerprinting system from YAML config
func InitializeFromYAML(configPath string) error {
	GlobalConfigManager = NewConfigManager(configPath)

	if err := GlobalConfigManager.LoadConfig(); err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if err := GlobalConfigManager.ValidateConfig(); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
	}

	if err := GlobalConfigManager.ConvertToLegacyFormat(); err != nil {
		return fmt.Errorf("failed to convert config: %w", err)
	}

	return nil
}
