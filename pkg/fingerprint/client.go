package fingerprint

import (
	"context"
	"fmt"
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
