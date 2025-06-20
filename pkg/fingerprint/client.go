package fingerprint

import (
	"context"
	"fmt"
	"sync"
	"time"
)

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
	mutex      sync.RWMutex // Add mutex for thread safety
}

// NewClient creates a new fingerprinting client
func NewClient(snmpClient SNMPClient) *Client {
	return &Client{
		snmpClient: snmpClient,
		timeout:    time.Second * 30,
		logger:     func(msg string) {}, // Default no-op logger
	}
}

// SetLogger sets a custom logger function in a thread-safe manner
func (c *Client) SetLogger(logger func(string)) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if logger != nil {
		c.logger = logger
	} else {
		c.logger = func(msg string) {} // Fallback to no-op if nil
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
	basicOIDs := map[string]string{
		"sysDescr":    "1.3.6.1.2.1.1.1.0",
		"sysContact":  "1.3.6.1.2.1.1.4.0",
		"sysName":     "1.3.6.1.2.1.1.5.0",
		"sysLocation": "1.3.6.1.2.1.1.6.0",
	}

	result := make(map[string]string)

	for name, oid := range basicOIDs {
		value, err := c.snmpClient.Get(oid)
		if err != nil {
			// Log error but continue with other OIDs
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

	// Create a context with timeout for the entire operation
	queryCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	c.log(fmt.Sprintf("Starting serial query of %d OIDs...", len(oids)))

	for i, oidEntry := range oids {
		// Check if context is cancelled
		select {
		case <-queryCtx.Done():
			c.log("Query operation cancelled or timed out")
			return fingerprintData
		default:
		}

		c.log(fmt.Sprintf("Querying %d/%d: %s (%s)", i+1, len(oids), oidEntry.Name, oidEntry.OID))

		// Create a timeout for individual request (shorter than overall timeout)
		requestCtx, requestCancel := context.WithTimeout(queryCtx, time.Second*10)

		// Create a channel to handle the SNMP request with timeout
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

		// Small delay between requests to be gentler on the device
		time.Sleep(100 * time.Millisecond)
	}

	c.log(fmt.Sprintf("Serial query complete: %d successful out of %d total", len(fingerprintData), len(oids)))
	return fingerprintData
}

func (c *Client) PerformFingerprinting(ctx context.Context, targetVendor string) (*FingerprintResult, error) {
	startTime := time.Now()

	c.log("Starting vendor fingerprinting...")

	// Step 1: Get basic SNMP information (including sysObjectID for device type detection)
	basicOIDs := map[string]string{
		"sysDescr":    "1.3.6.1.2.1.1.1.0",
		"sysContact":  "1.3.6.1.2.1.1.4.0",
		"sysName":     "1.3.6.1.2.1.1.5.0",
		"sysLocation": "1.3.6.1.2.1.1.6.0",
		"sysObjectID": "1.3.6.1.2.1.1.2.0", // Added for device type detection
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
	if detectedVendor == "aruba" {
		// Use device-type-aware selection for Aruba
		vendorOIDs = GetVendorOIDsWithDeviceType(detectedVendor, basicInfo)
		deviceType := DetectArubaDeviceType(basicInfo["sysDescr"], basicInfo["sysObjectID"])
		c.log(fmt.Sprintf("Detected Aruba device type: %s", deviceType))
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

	// Get basic SNMP information
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

	// Detect vendor
	detectedVendor, confidence, detectionMethod := DetectVendorComprehensive(
		basicInfo["sysDescr"],
		basicInfo["sysContact"],
		basicInfo["sysName"],
		basicInfo["sysLocation"],
	)

	// Create basic fingerprint data from system info
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

		// Small delay between vendor tests to be gentle on the device
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
		// If we got specific data, we can be more confident
		if detectedVendor == "unknown" {
			finalMethod = "fingerprint_oids"
			finalConfidence = "medium"

			// Try to detect vendor from entity description if found
			if entityDescr, exists := fingerprintData["Entity Description"]; exists {
				reDetectedVendor := DetectVendorFromSysDescr(entityDescr)
				if reDetectedVendor != "unknown" {
					finalVendor = reDetectedVendor
					finalMethod = "fingerprint_oids (Entity Description)"
					finalConfidence = "high"
				}
			}
		} else {
			// We had initial detection, and now confirmed with specific OIDs
			finalMethod += " + fingerprint_oids"
			switch finalConfidence {
			case "low":
				finalConfidence = "medium"
			case "medium":
				finalConfidence = "high"
			}
		}
	} else {
		// If no specific OID data was collected
		if detectedVendor != "unknown" {
			finalConfidence = "low"
		} else {
			finalConfidence = "none"
		}
	}

	return finalVendor, finalConfidence, finalMethod
}

// GetSupportedVendors returns a list of supported vendors
func GetSupportedVendors() []string {
	vendors := make([]string, 0, len(VendorFingerprints))
	for vendor := range VendorFingerprints {
		vendors = append(vendors, vendor)
	}
	return vendors
}
