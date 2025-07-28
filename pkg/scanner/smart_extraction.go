package main

import (
	"regexp"
	"strings"
)

// SmartFieldExtractor handles intelligent field extraction from SNMP data
type SmartFieldExtractor struct {
	vendorConfig *VendorFingerprintConfig
}

// NewSmartFieldExtractor creates a new smart field extractor
func NewSmartFieldExtractor(config *VendorFingerprintConfig) *SmartFieldExtractor {
	return &SmartFieldExtractor{
		vendorConfig: config,
	}
}

// ExtractAllFields performs smart extraction of model, serial, and firmware from ALL OID data
func (extractor *SmartFieldExtractor) ExtractAllFields(vendor string, snmpData map[string]string) (model, serial, firmware string) {
	if extractor.vendorConfig == nil {
		return extractor.extractFieldsGeneric(snmpData)
	}

	// Try vendor-specific extraction first
	model, serial, firmware = extractor.extractFieldsVendorSpecific(vendor, snmpData)

	// Fill in any missing fields with generic extraction
	if model == "" || serial == "" || firmware == "" {
		genModel, genSerial, genFirmware := extractor.extractFieldsGeneric(snmpData)
		if model == "" {
			model = genModel
		}
		if serial == "" {
			serial = genSerial
		}
		if firmware == "" {
			firmware = genFirmware
		}
	}

	return model, serial, firmware
}

// extractFieldsVendorSpecific extracts fields using vendor-specific rules from YAML
func (extractor *SmartFieldExtractor) extractFieldsVendorSpecific(vendor string, snmpData map[string]string) (model, serial, firmware string) {
	vendorConfig, exists := extractor.vendorConfig.Vendors[vendor]
	if !exists {
		return "", "", ""
	}

	// Create mapping of OID -> name for smart analysis
	oidNameMap := make(map[string]string)
	for _, fingerprintOID := range vendorConfig.FingerprintOIDs {
		if fingerprintOID.OID != "" && fingerprintOID.Name != "" {
			oidNameMap[fingerprintOID.OID] = strings.ToLower(fingerprintOID.Name)
		}
	}

	// Analyze collected SNMP data using OID names from YAML
	for oid, value := range snmpData {
		if value == "" || value == "<nil>" {
			continue
		}

		// Get the descriptive name for this OID from YAML
		oidName := oidNameMap[oid]

		// Smart detection based on OID name keywords
		if model == "" && extractor.isModelField(oidName) {
			model = strings.TrimSpace(value)
		}
		if serial == "" && extractor.isSerialField(oidName) {
			serial = strings.TrimSpace(value)
		}
		if firmware == "" && extractor.isFirmwareField(oidName) {
			firmware = strings.TrimSpace(value)
		}
	}

	// Also apply vendor-specific regex extraction rules
	allText := extractor.combineAllText(snmpData)

	if model == "" {
		model = extractor.applyExtractionRules(vendorConfig.ModelExtraction, allText)
	}
	if serial == "" {
		serial = extractor.applyExtractionRules(vendorConfig.SerialExtraction, allText)
	}
	if firmware == "" {
		firmware = extractor.applyExtractionRules(vendorConfig.FirmwareExtraction, allText)
	}

	return model, serial, firmware
}

// extractFieldsGeneric performs generic field extraction using standard patterns
func (extractor *SmartFieldExtractor) extractFieldsGeneric(snmpData map[string]string) (model, serial, firmware string) {
	// Standard OID patterns for common fields
	standardPatterns := map[string]string{
		// Common model OIDs
		"1.3.6.1.2.1.47.1.1.1.1.13.1": "model", // entPhysicalModelName
		"1.3.6.1.2.1.47.1.1.1.1.7.1":  "model", // entPhysicalName
		// Common serial OIDs
		"1.3.6.1.2.1.47.1.1.1.1.11.1": "serial", // entPhysicalSerialNum
		// Common firmware OIDs
		"1.3.6.1.2.1.47.1.1.1.1.10.1": "firmware", // entPhysicalSoftwareRev
		"1.3.6.1.2.1.47.1.1.1.1.9.1":  "firmware", // entPhysicalFirmwareRev
	}

	// Check standard OID patterns first
	for oid, fieldType := range standardPatterns {
		if value, exists := snmpData[oid]; exists && value != "" && value != "<nil>" {
			cleanValue := strings.TrimSpace(value)
			switch fieldType {
			case "model":
				if model == "" {
					model = cleanValue
				}
			case "serial":
				if serial == "" {
					serial = cleanValue
				}
			case "firmware":
				if firmware == "" {
					firmware = cleanValue
				}
			}
		}
	}

	// Generic keyword-based extraction from field names
	for fieldName, value := range snmpData {
		if value == "" || value == "<nil>" {
			continue
		}

		fieldLower := strings.ToLower(fieldName)
		cleanValue := strings.TrimSpace(value)

		if model == "" && extractor.isModelField(fieldLower) {
			model = cleanValue
		}
		if serial == "" && extractor.isSerialField(fieldLower) {
			serial = cleanValue
		}
		if firmware == "" && extractor.isFirmwareField(fieldLower) {
			firmware = cleanValue
		}
	}

	return model, serial, firmware
}

// Helper functions to identify field types based on keywords
func (extractor *SmartFieldExtractor) isModelField(fieldName string) bool {
	modelKeywords := []string{"model", "product", "type", "chassis", "platform"}
	for _, keyword := range modelKeywords {
		if strings.Contains(fieldName, keyword) {
			return true
		}
	}
	return false
}

func (extractor *SmartFieldExtractor) isSerialField(fieldName string) bool {
	serialKeywords := []string{"serial", "serialnumber", "serial_number", "service_tag", "servicetag"}
	for _, keyword := range serialKeywords {
		if strings.Contains(fieldName, keyword) {
			return true
		}
	}
	return false
}

func (extractor *SmartFieldExtractor) isFirmwareField(fieldName string) bool {
	firmwareKeywords := []string{"firmware", "version", "software", "os", "revision", "build"}
	for _, keyword := range firmwareKeywords {
		if strings.Contains(fieldName, keyword) {
			return true
		}
	}
	return false
}

// combineAllText combines all SNMP values for regex processing
func (extractor *SmartFieldExtractor) combineAllText(snmpData map[string]string) string {
	var allText strings.Builder
	for _, value := range snmpData {
		if value != "" && value != "<nil>" {
			allText.WriteString(value)
			allText.WriteString(" ")
		}
	}
	return strings.ToLower(allText.String())
}

// applyExtractionRules applies regex extraction rules from YAML configuration
func (extractor *SmartFieldExtractor) applyExtractionRules(rules []ExtractionRule, text string) string {
	for _, rule := range rules {
		if rule.Regex == "" {
			continue
		}

		regex, err := regexp.Compile(rule.Regex)
		if err != nil {
			continue
		}

		matches := regex.FindStringSubmatch(text)
		if len(matches) > rule.CaptureGroup {
			extracted := strings.TrimSpace(matches[rule.CaptureGroup])
			if extracted != "" {
				return extracted
			}
		}
	}
	return ""
}

// ExtractionRule represents a field extraction rule from YAML
type ExtractionRule struct {
	Regex        string   `yaml:"regex"`
	Priority     int      `yaml:"priority"`
	CaptureGroup int      `yaml:"capture_group"`
	DeviceTypes  []string `yaml:"device_types"`
	Description  string   `yaml:"description"`
}

// Add extraction rule fields to VendorConfig
type VendorConfigExtended struct {
	VendorConfig
	ModelExtraction    []ExtractionRule `yaml:"model_extraction"`
	SerialExtraction   []ExtractionRule `yaml:"serial_extraction"`
	FirmwareExtraction []ExtractionRule `yaml:"firmware_extraction"`
}
