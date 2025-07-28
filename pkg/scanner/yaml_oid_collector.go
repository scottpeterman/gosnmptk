package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/scottpeterman/gosnmptk/pkg/snmp"
)

// YAMLOIDCollector handles intelligent OID collection based on YAML configuration
type YAMLOIDCollector struct {
	client       *snmp.Client
	config       *VendorFingerprintConfig
	vendorLogger *VendorDetectionLogger
	timeout      time.Duration
}

// NewYAMLOIDCollector creates a new YAML-based OID collector
func NewYAMLOIDCollector(client *snmp.Client, config *VendorFingerprintConfig, logger *VendorDetectionLogger) *YAMLOIDCollector {
	return &YAMLOIDCollector{
		client:       client,
		config:       config,
		vendorLogger: logger,
		timeout:      10 * time.Second,
	}
}

// CollectAllFingerprintOIDs collects all fingerprint OIDs from YAML configuration
func (collector *YAMLOIDCollector) CollectAllFingerprintOIDs(ctx context.Context, result *CLIScanResult) error {
	if collector.config == nil {
		return fmt.Errorf("no YAML config available")
	}

	// Initialize vendor data if needed
	if result.VendorData == nil {
		result.VendorData = make(map[string]string)
	}

	// Collect standard system OIDs first
	collector.collectStandardOIDs(ctx, result)

	// Collect all vendor fingerprint OIDs
	collector.collectVendorFingerprintOIDs(ctx, result)

	// Collect generic extended OIDs
	collector.collectGenericOIDs(ctx, result)

	return nil
}

// collectStandardOIDs collects standard system OIDs
func (collector *YAMLOIDCollector) collectStandardOIDs(ctx context.Context, result *CLIScanResult) {
	standardOIDs := map[string]string{
		"System Description": "1.3.6.1.2.1.1.1.0",
		"System Name":        "1.3.6.1.2.1.1.5.0",
		"System Object ID":   "1.3.6.1.2.1.1.2.0",
		"System Up Time":     "1.3.6.1.2.1.1.3.0",
		"System Contact":     "1.3.6.1.2.1.1.4.0",
		"System Location":    "1.3.6.1.2.1.1.6.0",
		"System Services":    "1.3.6.1.2.1.1.7.0",
	}

	// Use common OIDs from YAML if available
	if len(collector.config.CommonOIDs) > 0 {
		for name, oid := range collector.config.CommonOIDs {
			standardOIDs[name] = oid
		}
	}

	for name, oid := range standardOIDs {
		collector.collectSingleOID(ctx, oid, name, result)
	}
}

// collectVendorFingerprintOIDs collects all vendor-specific fingerprint OIDs
func (collector *YAMLOIDCollector) collectVendorFingerprintOIDs(ctx context.Context, result *CLIScanResult) {
	// Collect fingerprint OIDs from ALL vendors (not just detected vendor)
	// This allows for vendor correction based on successful OID responses
	for vendorKey, vendorConfig := range collector.config.Vendors {
		if collector.vendorLogger != nil {
			collector.vendorLogger.LogVendorTest(vendorKey, 0, []string{}, []string{})
		}

		for _, fingerprintOID := range vendorConfig.FingerprintOIDs {
			oidName := fmt.Sprintf("%s_%s", vendorKey, fingerprintOID.Name)
			collector.collectSingleOID(ctx, fingerprintOID.OID, oidName, result)
		}
	}
}

// collectGenericOIDs collects generic extended OIDs
func (collector *YAMLOIDCollector) collectGenericOIDs(ctx context.Context, result *CLIScanResult) {
	// Standard Entity MIB OIDs
	genericOIDs := map[string]string{
		"Entity Model Name":        "1.3.6.1.2.1.47.1.1.1.1.13.1",
		"Entity Serial Number":     "1.3.6.1.2.1.47.1.1.1.1.11.1",
		"Entity Hardware Revision": "1.3.6.1.2.1.47.1.1.1.1.8.1",
		"Entity Software Revision": "1.3.6.1.2.1.47.1.1.1.1.10.1",
		"Entity Firmware Revision": "1.3.6.1.2.1.47.1.1.1.1.9.1",
		"Entity Manufacturer":      "1.3.6.1.2.1.47.1.1.1.1.12.1",
	}

	// Use generic OIDs from YAML if available
	if len(collector.config.GenericOIDs) > 0 {
		for _, genericOID := range collector.config.GenericOIDs {
			genericOIDs[genericOID.Name] = genericOID.OID
		}
	}

	for name, oid := range genericOIDs {
		collector.collectSingleOID(ctx, oid, name, result)
	}
}

// collectSingleOID collects a single OID with timeout and error handling
func (collector *YAMLOIDCollector) collectSingleOID(ctx context.Context, oid, name string, result *CLIScanResult) {
	// Create timeout context for this OID
	oidCtx, cancel := context.WithTimeout(ctx, collector.timeout)
	defer cancel()

	// Use a channel to handle timeout
	resultChan := make(chan struct {
		value string
		err   error
	}, 1)

	// Query OID in goroutine
	go func() {
		value, err := collector.client.Get(oid)
		resultChan <- struct {
			value string
			err   error
		}{value, err}
	}()

	// Wait for result or timeout
	select {
	case res := <-resultChan:
		if res.err == nil && collector.isValidSNMPResponse(res.value) {
			result.VendorData[name] = res.value
			if collector.vendorLogger != nil {
				collector.vendorLogger.LogPatternMatch("oid_collection", oid, res.value, true, false)
			}
		} else if collector.vendorLogger != nil {
			errorMsg := "invalid_response"
			if res.err != nil {
				errorMsg = res.err.Error()
			}
			collector.vendorLogger.LogError(result.IP, fmt.Sprintf("OID %s (%s) failed: %s", oid, name, errorMsg))
		}

	case <-oidCtx.Done():
		if collector.vendorLogger != nil {
			collector.vendorLogger.LogError(result.IP, fmt.Sprintf("OID %s (%s) timeout", oid, name))
		}
	}
}

// isValidSNMPResponse checks if SNMP response is valid and useful
func (collector *YAMLOIDCollector) isValidSNMPResponse(value string) bool {
	if value == "" {
		return false
	}

	// Invalid SNMP response patterns
	invalidResponses := []string{
		"No Such Object currently exists at this OID",
		"No Such Instance currently exists at this OID",
		"End of MIB",
		"NULL",
		"None",
		"\"\"",
		"<nil>",
		"noSuchObject",
		"noSuchInstance",
	}

	valueLower := strings.ToLower(value)
	for _, invalid := range invalidResponses {
		if strings.Contains(valueLower, strings.ToLower(invalid)) {
			return false
		}
	}

	return true
}

// PerformDefinitiveOIDDetection performs OID-based vendor detection first
func (collector *YAMLOIDCollector) PerformDefinitiveOIDDetection(ctx context.Context, result *CLIScanResult) (string, string, string) {
	if collector.config == nil {
		return "unknown", "none", "no_yaml_config"
	}

	// Test vendors in priority order
	for priority, vendorKey := range collector.config.DetectionRules.PriorityOrder {
		vendorConfig, exists := collector.config.Vendors[vendorKey]
		if !exists {
			continue
		}

		if collector.vendorLogger != nil {
			collector.vendorLogger.LogVendorTest(vendorKey, priority, []string{}, []string{})
		}

		// Test definitive OIDs for this vendor
		for _, fingerprintOID := range vendorConfig.FingerprintOIDs {
			if !fingerprintOID.Definitive {
				continue
			}

			// Test this definitive OID
			value, err := collector.client.Get(fingerprintOID.OID)
			if err != nil {
				continue
			}

			if !collector.isValidSNMPResponse(value) {
				continue
			}

			// Check expected values if specified
			if len(fingerprintOID.ExpectedValues) > 0 {
				matched := false
				for _, expectedValue := range fingerprintOID.ExpectedValues {
					if strings.Contains(strings.ToLower(value), strings.ToLower(expectedValue)) {
						matched = true
						break
					}
				}
				if !matched {
					continue
				}
			}

			// Definitive match found!
			if collector.vendorLogger != nil {
				collector.vendorLogger.LogDetectionResult(result.IP, vendorKey, "high", "definitive_oid_match")
			}

			// Store the successful OID data
			result.VendorData[fingerprintOID.Name] = value

			return vendorKey, "high", "definitive_oid_match"
		}
	}

	return "unknown", "none", "no_definitive_oid"
}
