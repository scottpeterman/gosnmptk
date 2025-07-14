package fingerprint

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Initialize the fingerprinting system
func init() {
	// Try to load YAML config on package initialization
	if err := InitializeFromYAML(""); err != nil {
		// If YAML config fails, we'll fall back to empty maps
		// (which will be populated by hardcoded fallbacks if needed)
		fmt.Printf("Warning: Could not load YAML config: %v\n", err)
	}
}

// SNMPClient interface for SNMP operations - simplified to avoid type conflicts
type SNMPClient interface {
	Get(oid string) (string, error)
	TestConnection() (string, error)
}

// Client performs vendor fingerprinting using SNMP
type Client struct {
	snmpClient SNMPClient
	timeout    time.Duration
	logger     func(string)
	mutex      sync.RWMutex
}

// NewClient creates a new fingerprinting client
func NewClient(snmpClient SNMPClient) *Client {
	client := &Client{
		snmpClient: snmpClient,
		timeout:    time.Second * 30,
		logger:     func(msg string) {},
	}

	// Apply YAML config timeouts if available
	if GlobalConfigManager != nil && GlobalConfigManager.GetConfig() != nil {
		timeout, _, _ := GlobalConfigManager.GetScanningConfig()
		client.timeout = timeout
	}

	return client
}

// SetLogger sets a custom logger function in a thread-safe manner
func (c *Client) SetLogger(logger func(string)) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if logger != nil {
		c.logger = logger
	} else {
		c.logger = func(msg string) {}
	}
}

// log safely calls the logger function
func (c *Client) log(msg string) {
	c.mutex.RLock()
	logger := c.logger
	c.mutex.RUnlock()

	if logger != nil {
		logger(msg)
	}
}

// SetTimeout sets the fingerprinting timeout
func (c *Client) SetTimeout(timeout time.Duration) {
	c.timeout = timeout
}

// getBasicInfo retrieves basic SNMP information using individual GET requests
func (c *Client) getBasicInfo() (map[string]string, error) {
	basicOIDs := CommonOIDs
	if len(basicOIDs) == 0 {
		// Fallback to hardcoded if YAML config not loaded
		basicOIDs = map[string]string{
			"sysDescr":    "1.3.6.1.2.1.1.1.0",
			"sysContact":  "1.3.6.1.2.1.1.4.0",
			"sysName":     "1.3.6.1.2.1.1.5.0",
			"sysLocation": "1.3.6.1.2.1.1.6.0",
		}
	}

	result := make(map[string]string)

	for name, oid := range basicOIDs {
		value, err := c.snmpClient.Get(oid)
		if err != nil {
			c.log(fmt.Sprintf("Failed to get %s: %v", name, err))
			continue
		}
		result[name] = value
	}

	return result, nil
}

// queryOIDsSerially queries multiple OIDs one at a time for better stability
func (c *Client) queryOIDsSerially(ctx context.Context, oids []OIDEntry) map[string]string {
	fingerprintData := make(map[string]string)

	// Get timing config from YAML if available
	var oidTimeout time.Duration
	var delay time.Duration
	if GlobalConfigManager != nil && GlobalConfigManager.GetConfig() != nil {
		_, oidTimeout, delay = GlobalConfigManager.GetScanningConfig()
	} else {
		oidTimeout = time.Second * 10
		delay = 100 * time.Millisecond
	}

	queryCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	c.log(fmt.Sprintf("Starting serial query of %d OIDs...", len(oids)))

	for i, oidEntry := range oids {
		select {
		case <-queryCtx.Done():
			c.log("Query operation cancelled or timed out")
			return fingerprintData
		default:
		}

		c.log(fmt.Sprintf("Querying %d/%d: %s (%s)", i+1, len(oids), oidEntry.Name, oidEntry.OID))

		requestCtx, requestCancel := context.WithTimeout(queryCtx, oidTimeout)

		resultChan := make(chan struct {
			value string
			err   error
		}, 1)

		go func() {
			value, err := c.snmpClient.Get(oidEntry.OID)
			resultChan <- struct {
				value string
				err   error
			}{value, err}
		}()

		select {
		case result := <-resultChan:
			if result.err == nil && IsValidSNMPValue(result.value) {
				fingerprintData[oidEntry.Name] = result.value
				c.log(fmt.Sprintf("SUCCESS %s: %s", oidEntry.Name, result.value))
			} else if result.err != nil {
				c.log(fmt.Sprintf("FAILED %s: %v", oidEntry.Name, result.err))
			} else {
				c.log(fmt.Sprintf("INVALID %s: %s", oidEntry.Name, result.value))
			}
		case <-requestCtx.Done():
			c.log(fmt.Sprintf("TIMEOUT %s (%s)", oidEntry.Name, oidEntry.OID))
		}

		requestCancel()
		time.Sleep(delay)
	}

	c.log(fmt.Sprintf("Serial query complete: %d successful out of %d total", len(fingerprintData), len(oids)))
	return fingerprintData
}

// PerformFingerprinting performs standard vendor fingerprinting (original method)
func (c *Client) PerformFingerprinting(ctx context.Context, targetVendor string) (*FingerprintResult, error) {
	startTime := time.Now()

	c.log("Starting vendor fingerprinting...")

	// Step 1: Get basic SNMP information
	basicOIDs := map[string]string{
		"sysDescr":    "1.3.6.1.2.1.1.1.0",
		"sysContact":  "1.3.6.1.2.1.1.4.0",
		"sysName":     "1.3.6.1.2.1.1.5.0",
		"sysLocation": "1.3.6.1.2.1.1.6.0",
		"sysObjectID": "1.3.6.1.2.1.1.2.0",
	}

	// Use CommonOIDs from YAML if available
	if len(CommonOIDs) > 0 {
		basicOIDs = CommonOIDs
		// Ensure sysObjectID is included for device type detection
		basicOIDs["sysObjectID"] = "1.3.6.1.2.1.1.2.0"
	}

	basicInfo := make(map[string]string)
	for name, oid := range basicOIDs {
		value, err := c.snmpClient.Get(oid)
		if err != nil {
			c.log(fmt.Sprintf("Failed to get %s: %v", name, err))
			continue
		}
		basicInfo[name] = value
	}

	if len(basicInfo) == 0 {
		return &FingerprintResult{
			DetectedVendor:  "unknown",
			Confidence:      "none",
			DetectionMethod: "error",
			FingerprintData: make(map[string]string),
			ScanDuration:    time.Since(startTime),
			Success:         false,
			ErrorMessage:    "Failed to get any basic SNMP info",
		}, fmt.Errorf("failed to get basic SNMP info")
	}

	c.log("Retrieved basic SNMP information for device")

	// Step 2: Detect vendor from basic information
	detectedVendor, confidence, detectionMethod := DetectVendorComprehensive(
		basicInfo["sysDescr"],
		basicInfo["sysContact"],
		basicInfo["sysName"],
		basicInfo["sysLocation"],
	)

	c.log(fmt.Sprintf("Initial detection: Vendor=%s, Confidence=%s, Method=%s",
		detectedVendor, confidence, detectionMethod))

	// Use target vendor if specified and detected vendor is unknown
	if targetVendor != "" && targetVendor != "auto-detect" && detectedVendor == "unknown" {
		detectedVendor = targetVendor
		confidence = "manual"
		detectionMethod = "manual_override"
		c.log(fmt.Sprintf("Using manual vendor override: %s", targetVendor))
	}

	// Step 3: Get vendor-specific OIDs with device type awareness
	var vendorOIDs []OIDEntry
	if detectedVendor == "aruba" || detectedVendor == "hp_printer" {
		vendorOIDs = GetVendorOIDsWithDeviceType(detectedVendor, basicInfo)
		deviceType := DetectDeviceType(detectedVendor, basicInfo["sysDescr"], basicInfo["sysObjectID"])
		c.log(fmt.Sprintf("Detected device type: %s", deviceType))
	} else {
		vendorOIDs = GetVendorOIDs(detectedVendor)
	}

	if len(vendorOIDs) == 0 {
		c.log("No vendor-specific OIDs found, returning basic detection only")
		return &FingerprintResult{
			DetectedVendor:  detectedVendor,
			Confidence:      confidence,
			DetectionMethod: detectionMethod,
			FingerprintData: make(map[string]string),
			ScanDuration:    time.Since(startTime),
			Success:         true,
		}, nil
	}

	// Step 4: Query vendor-specific OIDs serially
	c.log(fmt.Sprintf("Querying %d vendor-specific OIDs serially...", len(vendorOIDs)))

	fingerprintData := c.queryOIDsSerially(ctx, vendorOIDs)

	// Step 5: Refine detection based on collected data
	finalVendor, finalConfidence, finalMethod := c.refineDetection(
		detectedVendor, confidence, detectionMethod, fingerprintData)

	scanDuration := time.Since(startTime)

	result := &FingerprintResult{
		DetectedVendor:  finalVendor,
		Confidence:      finalConfidence,
		DetectionMethod: finalMethod,
		FingerprintData: fingerprintData,
		ScanDuration:    scanDuration,
		Success:         true,
	}

	c.log(fmt.Sprintf("Fingerprinting complete: %s detected with %d fields in %v",
		finalVendor, len(fingerprintData), scanDuration))

	return result, nil
}

// PerformAdvancedFingerprinting performs sophisticated vendor detection using OID validation
func (c *Client) PerformAdvancedFingerprinting(ctx context.Context, targetVendor string) (*FingerprintResult, error) {
	startTime := time.Now()

	c.log("Starting advanced vendor fingerprinting...")

	// Step 1: Get basic SNMP information (same as before)
	basicOIDs := map[string]string{
		"sysDescr":    "1.3.6.1.2.1.1.1.0",
		"sysContact":  "1.3.6.1.2.1.1.4.0",
		"sysName":     "1.3.6.1.2.1.1.5.0",
		"sysLocation": "1.3.6.1.2.1.1.6.0",
		"sysObjectID": "1.3.6.1.2.1.1.2.0",
	}

	// Use CommonOIDs from YAML if available
	if len(CommonOIDs) > 0 {
		basicOIDs = CommonOIDs
		// Ensure sysObjectID is included for device type detection
		basicOIDs["sysObjectID"] = "1.3.6.1.2.1.1.2.0"
	}

	basicInfo := make(map[string]string)
	for name, oid := range basicOIDs {
		value, err := c.snmpClient.Get(oid)
		if err != nil {
			c.log(fmt.Sprintf("Failed to get %s: %v", name, err))
			continue
		}
		basicInfo[name] = value
	}

	if len(basicInfo) == 0 {
		return &FingerprintResult{
			DetectedVendor:  "unknown",
			Confidence:      "none",
			DetectionMethod: "error",
			FingerprintData: make(map[string]string),
			ScanDuration:    time.Since(startTime),
			Success:         false,
			ErrorMessage:    "Failed to get any basic SNMP info",
		}, fmt.Errorf("failed to get basic SNMP info")
	}

	c.log("Retrieved basic SNMP information for device")

	// Step 2: Use advanced vendor detection instead of the basic one
	detectedVendor, confidence, detectionMethod := DetectVendorAdvanced(
		basicInfo["sysDescr"],
		basicInfo["sysContact"],
		basicInfo["sysName"],
		basicInfo["sysLocation"],
		c.snmpClient, // Pass SNMP client for OID validation
	)

	c.log(fmt.Sprintf("Advanced detection: Vendor=%s, Confidence=%s, Method=%s",
		detectedVendor, confidence, detectionMethod))

	// Use target vendor if specified and detected vendor is unknown
	if targetVendor != "" && targetVendor != "auto-detect" && detectedVendor == "unknown" {
		detectedVendor = targetVendor
		confidence = "manual"
		detectionMethod = "manual_override"
		c.log(fmt.Sprintf("Using manual vendor override: %s", targetVendor))
	}

	// Step 3: Get vendor-specific OIDs (same as before but with better vendor detection)
	var vendorOIDs []OIDEntry
	if detectedVendor == "aruba" || detectedVendor == "hp_printer" {
		vendorOIDs = GetVendorOIDsWithDeviceType(detectedVendor, basicInfo)
		deviceType := DetectDeviceType(detectedVendor, basicInfo["sysDescr"], basicInfo["sysObjectID"])
		c.log(fmt.Sprintf("Detected device type: %s", deviceType))
	} else {
		vendorOIDs = GetVendorOIDs(detectedVendor)
	}

	if len(vendorOIDs) == 0 {
		c.log("No vendor-specific OIDs found, returning basic detection only")
		return &FingerprintResult{
			DetectedVendor:  detectedVendor,
			Confidence:      confidence,
			DetectionMethod: detectionMethod,
			FingerprintData: make(map[string]string),
			ScanDuration:    time.Since(startTime),
			Success:         true,
		}, nil
	}

	// Step 4: Query vendor-specific OIDs serially
	c.log(fmt.Sprintf("Querying %d vendor-specific OIDs serially...", len(vendorOIDs)))

	fingerprintData := c.queryOIDsSerially(ctx, vendorOIDs)

	// Step 5: Refine detection based on collected data
	finalVendor, finalConfidence, finalMethod := c.refineDetection(
		detectedVendor, confidence, detectionMethod, fingerprintData)

	scanDuration := time.Since(startTime)

	result := &FingerprintResult{
		DetectedVendor:  finalVendor,
		Confidence:      finalConfidence,
		DetectionMethod: finalMethod,
		FingerprintData: fingerprintData,
		ScanDuration:    scanDuration,
		Success:         true,
	}

	c.log(fmt.Sprintf("Advanced fingerprinting complete: %s detected with %d fields in %v",
		finalVendor, len(fingerprintData), scanDuration))

	return result, nil
}

// TestConnection tests the SNMP connection
func (c *Client) TestConnection() error {
	c.log("Testing SNMP connection...")

	_, err := c.snmpClient.TestConnection()
	if err != nil {
		return fmt.Errorf("connection test failed: %w", err)
	}

	c.log("Connection test successful")
	return nil
}

// QuickVendorDetection performs quick vendor detection using basic SNMP data only
func (c *Client) QuickVendorDetection() (*FingerprintResult, error) {
	startTime := time.Now()

	c.log("Performing quick vendor detection...")

	basicInfo, err := c.getBasicInfo()
	if err != nil {
		return &FingerprintResult{
			DetectedVendor:  "unknown",
			Confidence:      "none",
			DetectionMethod: "error",
			FingerprintData: make(map[string]string),
			ScanDuration:    time.Since(startTime),
			Success:         false,
			ErrorMessage:    fmt.Sprintf("Failed to get basic SNMP info: %v", err),
		}, err
	}

	detectedVendor, confidence, detectionMethod := DetectVendorComprehensive(
		basicInfo["sysDescr"],
		basicInfo["sysContact"],
		basicInfo["sysName"],
		basicInfo["sysLocation"],
	)

	fingerprintData := make(map[string]string)
	if basicInfo["sysDescr"] != "" {
		fingerprintData["System Description"] = basicInfo["sysDescr"]
	}
	if basicInfo["sysContact"] != "" {
		fingerprintData["System Contact"] = basicInfo["sysContact"]
	}
	if basicInfo["sysName"] != "" {
		fingerprintData["System Name"] = basicInfo["sysName"]
	}
	if basicInfo["sysLocation"] != "" {
		fingerprintData["System Location"] = basicInfo["sysLocation"]
	}

	result := &FingerprintResult{
		DetectedVendor:  detectedVendor,
		Confidence:      confidence,
		DetectionMethod: detectionMethod,
		FingerprintData: fingerprintData,
		ScanDuration:    time.Since(startTime),
		Success:         true,
	}

	c.log(fmt.Sprintf("Quick detection complete: %s detected", detectedVendor))

	return result, nil
}

// TestAdvancedDetection provides a simple way to test the advanced detection
func (c *Client) TestAdvancedDetection() (*FingerprintResult, error) {
	c.log("Testing advanced vendor detection...")

	// Get basic system info
	basicInfo, err := c.getBasicInfo()
	if err != nil {
		return &FingerprintResult{
			DetectedVendor:  "unknown",
			Confidence:      "none",
			DetectionMethod: "error",
			FingerprintData: make(map[string]string),
			Success:         false,
			ErrorMessage:    fmt.Sprintf("Failed to get basic info: %v", err),
		}, err
	}

	// Run advanced detection
	detectedVendor, confidence, detectionMethod := DetectVendorAdvanced(
		basicInfo["sysDescr"],
		basicInfo["sysContact"],
		basicInfo["sysName"],
		basicInfo["sysLocation"],
		c.snmpClient,
	)

	// Create fingerprint data from basic info
	fingerprintData := make(map[string]string)
	if basicInfo["sysDescr"] != "" {
		fingerprintData["System Description"] = basicInfo["sysDescr"]
	}

	result := &FingerprintResult{
		DetectedVendor:  detectedVendor,
		Confidence:      confidence,
		DetectionMethod: detectionMethod,
		FingerprintData: fingerprintData,
		Success:         true,
	}

	c.log(fmt.Sprintf("Advanced detection test complete: %s", detectedVendor))
	return result, nil
}

// CompareDetectionMethods compares old vs new detection for testing
func (c *Client) CompareDetectionMethods() {
	c.log("Comparing detection methods...")

	// Get basic info
	basicInfo, err := c.getBasicInfo()
	if err != nil {
		c.log(fmt.Sprintf("Failed to get basic info: %v", err))
		return
	}

	// Old method
	oldVendor, oldConf, oldMethod := DetectVendorComprehensive(
		basicInfo["sysDescr"],
		basicInfo["sysContact"],
		basicInfo["sysName"],
		basicInfo["sysLocation"],
	)

	// New method
	newVendor, newConf, newMethod := DetectVendorAdvanced(
		basicInfo["sysDescr"],
		basicInfo["sysContact"],
		basicInfo["sysName"],
		basicInfo["sysLocation"],
		c.snmpClient,
	)

	fmt.Printf("Detection Comparison:\n")
	fmt.Printf("  Old: %s (confidence: %s, method: %s)\n", oldVendor, oldConf, oldMethod)
	fmt.Printf("  New: %s (confidence: %s, method: %s)\n", newVendor, newConf, newMethod)

	if oldVendor != newVendor {
		fmt.Printf("  *** DIFFERENT RESULTS ***\n")
	} else {
		fmt.Printf("  Results match\n")
	}
}

// TestAllVendors tests fingerprinting against all known vendors (serial version)
func (c *Client) TestAllVendors(ctx context.Context) (map[string]*FingerprintResult, error) {
	c.log("Testing fingerprinting against all known vendors...")

	results := make(map[string]*FingerprintResult)
	vendors := []string{"auto-detect"}

	// Add all known vendors
	for vendor := range VendorFingerprints {
		vendors = append(vendors, vendor)
	}
	vendors = append(vendors, "generic")

	for i, vendor := range vendors {
		c.log(fmt.Sprintf("Testing %d/%d: %s fingerprinting...", i+1, len(vendors), vendor))

		result, err := c.PerformFingerprinting(ctx, vendor)
		if err != nil {
			result = &FingerprintResult{
				DetectedVendor:  "unknown",
				Confidence:      "none",
				DetectionMethod: "error",
				FingerprintData: make(map[string]string),
				ScanDuration:    0,
				Success:         false,
				ErrorMessage:    err.Error(),
			}
		}

		results[vendor] = result

		// Small delay between vendor tests
		time.Sleep(200 * time.Millisecond)
	}

	c.log("All vendor testing complete")
	return results, nil
}

// refineDetection refines vendor detection based on collected fingerprint data
func (c *Client) refineDetection(detectedVendor, confidence, detectionMethod string,
	fingerprintData map[string]string) (string, string, string) {

	finalVendor := detectedVendor
	finalConfidence := confidence
	finalMethod := detectionMethod

	if len(fingerprintData) > 0 {
		if detectedVendor == "unknown" {
			finalMethod = "fingerprint_oids"
			finalConfidence = "medium"

			if entityDescr, exists := fingerprintData["Entity Description"]; exists {
				reDetectedVendor := DetectVendorFromSysDescr(entityDescr)
				if reDetectedVendor != "unknown" {
					finalVendor = reDetectedVendor
					finalMethod = "fingerprint_oids (Entity Description)"
					finalConfidence = "high"
				}
			}
		} else {
			finalMethod += " + fingerprint_oids"
			switch finalConfidence {
			case "low":
				finalConfidence = "medium"
			case "medium":
				finalConfidence = "high"
			}
		}
	} else {
		if detectedVendor != "unknown" {
			finalConfidence = "low"
		} else {
			finalConfidence = "none"
		}
	}

	return finalVendor, finalConfidence, finalMethod
}

// Add this method to your existing client.go file, right after the TestConnection() method

// TestOIDBasedDetection performs OID-based vendor detection to fix Cisco/ION confusion
func (c *Client) TestOIDBasedDetection() error {
	c.log("Testing OID-based vendor detection...")

	// Get basic info first
	basicInfo, err := c.getBasicInfo()
	if err != nil {
		c.log(fmt.Sprintf("Failed to get basic info: %v", err))
		return err
	}

	// Old pattern-based detection
	oldVendor, oldConf, oldMethod := DetectVendorComprehensive(
		basicInfo["sysDescr"],
		basicInfo["sysContact"],
		basicInfo["sysName"],
		basicInfo["sysLocation"],
	)

	// New OID-based detection
	newVendor := "unknown"
	newConf := "none"
	newMethod := "pattern_fallback"

	// Test definitive vendor OIDs
	if value, err := c.snmpClient.Get("1.3.6.1.4.1.9.1.2694"); err == nil && value != "" {
		newVendor = "cisco"
		newConf = "high"
		newMethod = "cisco_catalyst_oid"
		c.log(fmt.Sprintf("Cisco Catalyst OID responded: %s", value))
	} else if value, err := c.snmpClient.Get("1.3.6.1.4.1.9.1.2137"); err == nil && value != "" {
		newVendor = "cisco"
		newConf = "high"
		newMethod = "cisco_catalyst_old_oid"
		c.log(fmt.Sprintf("Cisco Catalyst (old) OID responded: %s", value))
	} else if value, err := c.snmpClient.Get("1.3.6.1.4.1.25461.2.3.36"); err == nil && value != "" {
		newVendor = "palo_alto"
		newConf = "high"
		newMethod = "palo_alto_oid"
		c.log(fmt.Sprintf("Palo Alto OID responded: %s", value))
	} else if value, err := c.snmpClient.Get("1.3.6.1.4.1.50114.11.1.10.3000"); err == nil && value != "" {
		newVendor = "ion"
		newConf = "high"
		newMethod = "ion_oid"
		c.log(fmt.Sprintf("ION OID responded: %s", value))
	} else if value, err := c.snmpClient.Get("1.3.6.1.4.1.13315.2.1"); err == nil && value != "" {
		newVendor = "bluecat"
		newConf = "high"
		newMethod = "bluecat_oid"
		c.log(fmt.Sprintf("BlueCat OID responded: %s", value))
	} else {
		// No definitive OIDs responded, use pattern matching
		newVendor = oldVendor
		newConf = oldConf
		newMethod = oldMethod
		c.log("No definitive OIDs responded, using pattern matching")
	}

	c.log("=== Detection Comparison ===")
	c.log(fmt.Sprintf("Pattern-based: %s (confidence: %s, method: %s)", oldVendor, oldConf, oldMethod))
	c.log(fmt.Sprintf("OID-based:     %s (confidence: %s, method: %s)", newVendor, newConf, newMethod))

	if oldVendor != newVendor {
		c.log("*** METHODS DISAGREE - OID-based detection is more reliable ***")
	} else {
		c.log("✓ Both methods agree")
	}

	return nil
}

// Add this method to your existing client.go file

// TestYAMLBasedDetection performs OID-based vendor detection using YAML configuration
func (c *Client) TestYAMLBasedDetection() error {
	c.log("Testing YAML-based OID vendor detection...")

	// Get basic info first
	basicInfo, err := c.getBasicInfo()
	if err != nil {
		c.log(fmt.Sprintf("Failed to get basic info: %v", err))
		return err
	}

	// Old pattern-based detection
	oldVendor, oldConf, oldMethod := DetectVendorComprehensive(
		basicInfo["sysDescr"],
		basicInfo["sysContact"],
		basicInfo["sysName"],
		basicInfo["sysLocation"],
	)

	// New YAML-driven OID detection
	newVendor, newConf, newMethod := c.detectVendorByDefinitiveOIDs()

	// If no definitive OID match, fall back to pattern matching
	if newVendor == "unknown" {
		newVendor = oldVendor
		newConf = oldConf
		newMethod = oldMethod + "_fallback"
	}

	c.log("=== Detection Comparison ===")
	c.log(fmt.Sprintf("Pattern-based: %s (confidence: %s, method: %s)", oldVendor, oldConf, oldMethod))
	c.log(fmt.Sprintf("YAML OID-based: %s (confidence: %s, method: %s)", newVendor, newConf, newMethod))

	if oldVendor != newVendor {
		c.log("*** METHODS DISAGREE - YAML OID-based detection is more reliable ***")
	} else {
		c.log("✓ Both methods agree")
	}

	return nil
}

// detectVendorByDefinitiveOIDs uses YAML config to test definitive vendor OIDs
func (c *Client) detectVendorByDefinitiveOIDs() (vendor, confidence, method string) {
	if GlobalConfigManager == nil || GlobalConfigManager.GetConfig() == nil {
		c.log("No YAML config available for definitive OID testing")
		return "unknown", "none", "no_yaml_config"
	}

	config := GlobalConfigManager.GetConfig()

	// Test vendors in priority order
	for _, vendorKey := range config.DetectionRules.PriorityOrder {
		vendorConfig, exists := config.Vendors[vendorKey]
		if !exists {
			continue
		}

		c.log(fmt.Sprintf("Testing definitive OIDs for vendor: %s", vendorKey))

		// Test each fingerprint OID for this vendor
		for _, yamlOID := range vendorConfig.FingerprintOIDs {
			// Skip non-definitive OIDs
			if !yamlOID.Definitive {
				continue
			}

			c.log(fmt.Sprintf("  Testing definitive OID: %s (%s)", yamlOID.OID, yamlOID.Name))

			value, err := c.snmpClient.Get(yamlOID.OID)
			if err != nil {
				c.log(fmt.Sprintf("    FAILED: %v", err))
				continue
			}

			// Check if we got a valid response
			if !IsValidSNMPValue(value) {
				c.log(fmt.Sprintf("    INVALID: %s", value))
				continue
			}

			c.log(fmt.Sprintf("    SUCCESS: %s", value))

			// If expected values are specified, check them
			if len(yamlOID.ExpectedValues) > 0 {
				matched := false
				for _, expectedValue := range yamlOID.ExpectedValues {
					if strings.Contains(strings.ToLower(value), strings.ToLower(expectedValue)) {
						matched = true
						break
					}
				}
				if !matched {
					c.log(fmt.Sprintf("    VALUE MISMATCH: got '%s', expected one of %v", value, yamlOID.ExpectedValues))
					continue
				}
				c.log(fmt.Sprintf("    VALUE MATCHED: %s", value))
			}

			// We have a definitive match!
			c.log(fmt.Sprintf("*** DEFINITIVE MATCH: %s via %s ***", vendorKey, yamlOID.Name))
			return vendorKey, "high", fmt.Sprintf("definitive_oid_%s", yamlOID.Name)
		}
	}

	c.log("No definitive OID matches found")
	return "unknown", "none", "no_definitive_oid"
}

// GetDefinitiveOIDsFromYAML returns all definitive OIDs from YAML config (for debugging)
func (c *Client) GetDefinitiveOIDsFromYAML() map[string][]string {
	definitiveOIDs := make(map[string][]string)

	if GlobalConfigManager == nil || GlobalConfigManager.GetConfig() == nil {
		return definitiveOIDs
	}

	config := GlobalConfigManager.GetConfig()

	for vendorKey, vendorConfig := range config.Vendors {
		var oids []string
		for _, yamlOID := range vendorConfig.FingerprintOIDs {
			if yamlOID.Definitive {
				oids = append(oids, fmt.Sprintf("%s (%s)", yamlOID.OID, yamlOID.Name))
			}
		}
		if len(oids) > 0 {
			definitiveOIDs[vendorKey] = oids
		}
	}

	return definitiveOIDs
}

// ShowDefinitiveOIDs displays all definitive OIDs from YAML config
func (c *Client) ShowDefinitiveOIDs() {
	c.log("=== Definitive OIDs from YAML Config ===")

	definitiveOIDs := c.GetDefinitiveOIDsFromYAML()

	if len(definitiveOIDs) == 0 {
		c.log("No definitive OIDs found in YAML config")
		return
	}

	for vendor, oids := range definitiveOIDs {
		c.log(fmt.Sprintf("%s:", vendor))
		for _, oid := range oids {
			c.log(fmt.Sprintf("  - %s", oid))
		}
	}
}
