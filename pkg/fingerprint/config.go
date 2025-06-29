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

// LoadConfig loads the YAML configuration from file
func (cm *ConfigManager) LoadConfig() error {
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

	for _, path := range possiblePaths {
		if path == "" {
			continue
		}

		configData, err = ioutil.ReadFile(path)
		if err == nil {
			usedPath = path
			break
		}
	}

	if err != nil {
		return fmt.Errorf("failed to read config file from any location: %w", err)
	}

	var config YAMLConfig
	if err := yaml.Unmarshal(configData, &config); err != nil {
		return fmt.Errorf("failed to parse YAML config: %w", err)
	}

	cm.config = &config
	cm.configPath = usedPath
	cm.lastLoaded = time.Now()

	return nil
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

// DetectVendorFromConfig uses YAML config for vendor detection
func (cm *ConfigManager) DetectVendorFromConfig(sysDescr, sysContact, sysName, sysLocation string) (vendor, confidence, method string) {
	if cm.config == nil {
		return DetectVendorComprehensive(sysDescr, sysContact, sysName, sysLocation) // Fallback
	}

	// Use priority order from config
	for _, vendorKey := range cm.config.DetectionRules.PriorityOrder {
		vendorConfig, exists := cm.config.Vendors[vendorKey]
		if !exists {
			continue
		}

		// Check sysDescr first
		if sysDescr != "" {
			if cm.matchesPatterns(sysDescr, vendorConfig.DetectionPatterns, vendorConfig.ExclusionPatterns) {
				return vendorKey, "high", "sysDescr"
			}
		}

		// Check sysContact
		if sysContact != "" {
			if cm.matchesPatterns(sysContact, vendorConfig.DetectionPatterns, vendorConfig.ExclusionPatterns) {
				return vendorKey, "medium", "sysContact"
			}
		}

		// Check sysName
		if sysName != "" {
			if cm.matchesPatterns(sysName, vendorConfig.DetectionPatterns, vendorConfig.ExclusionPatterns) {
				return vendorKey, "low", "sysName"
			}
		}

		// Check sysLocation
		if sysLocation != "" {
			if cm.matchesPatterns(sysLocation, vendorConfig.DetectionPatterns, vendorConfig.ExclusionPatterns) {
				return vendorKey, "low", "sysLocation"
			}
		}
	}

	return "unknown", "none", "no_detection"
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
