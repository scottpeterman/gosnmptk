// pkg/persistence/bridge.go
package persistence

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// LegacyFingerprint represents the existing fingerprint structure
// This allows us to bridge between old and new systems without breaking changes
type LegacyFingerprint struct {
	IPAddress       string            `json:"ip_address"`
	Vendor          string            `json:"vendor"`
	DeviceType      string            `json:"device_type"`
	Model           string            `json:"model,omitempty"`
	SerialNumber    string            `json:"serial_number,omitempty"`
	OSVersion       string            `json:"os_version,omitempty"`
	FirmwareVersion string            `json:"firmware_version,omitempty"`
	SysObjectID     string            `json:"sys_object_id,omitempty"`
	SysDescr        string            `json:"sys_descr,omitempty"`
	SNMPData        map[string]string `json:"snmp_data"`
	ConfidenceScore int               `json:"confidence_score"`
	DetectionMethod string            `json:"detection_method"`
}

// PersistenceBridge provides non-breaking integration with existing code
type PersistenceBridge struct {
	manager *PersistenceManager
	enabled bool
}

// NewPersistenceBridge creates a new bridge that can be optionally enabled
func NewPersistenceBridge(dbPath string, enabled bool) *PersistenceBridge {
	var manager *PersistenceManager

	if enabled {
		manager = NewPersistenceManager(dbPath)
		// Try to load existing database, create new if needed
		if err := manager.LoadDatabase(); err != nil {
			fmt.Printf("Warning: Failed to load database: %v\n", err)
		}

		// Start auto-save
		manager.StartAutoSave()
	}

	return &PersistenceBridge{
		manager: manager,
		enabled: enabled,
	}
}

// RecordScanResult records a scan result using the new persistence system
// This can be called from existing code without breaking anything
func (pb *PersistenceBridge) RecordScanResult(fingerprint LegacyFingerprint) {
	if !pb.enabled || pb.manager == nil {
		return // Silently do nothing if persistence is disabled
	}

	// Convert legacy fingerprint to new DeviceFingerprint format
	newFingerprint := pb.convertLegacyFingerprint(fingerprint)

	// Generate session ID for this scan
	sessionID := pb.generateSessionID()

	// Create a minimal scan session
	session := ScanSession{
		ID:           sessionID,
		Timestamp:    time.Now(),
		TargetIP:     fingerprint.IPAddress,
		ScanType:     "single_device",
		Duration:     time.Second, // Placeholder
		DevicesFound: 1,
		Results:      []DeviceFingerprint{newFingerprint},
		Errors:       []ScanError{},
	}

	// Use the advanced deduplication logic (we'll add this next)
	pb.processFingerprint(newFingerprint, sessionID)

	// Record the session
	pb.manager.AddSession(session)
}

// RecordBulkScanResults records multiple scan results as a single session
func (pb *PersistenceBridge) RecordBulkScanResults(fingerprints []LegacyFingerprint, scanType string) {
	if !pb.enabled || pb.manager == nil {
		return
	}

	sessionID := pb.generateSessionID()
	startTime := time.Now()

	var results []DeviceFingerprint
	var errors []ScanError

	for _, fingerprint := range fingerprints {
		newFingerprint := pb.convertLegacyFingerprint(fingerprint)
		results = append(results, newFingerprint)

		// Process each fingerprint for deduplication
		pb.processFingerprint(newFingerprint, sessionID)
	}

	session := ScanSession{
		ID:           sessionID,
		Timestamp:    startTime,
		TargetIP:     "bulk_scan",
		ScanType:     scanType,
		Duration:     time.Since(startTime),
		DevicesFound: len(results),
		Results:      results,
		Errors:       errors,
	}

	pb.manager.AddSession(session)
}

// GetAggregateDevices returns all devices discovered across all scans
// This provides the main benefit of the new system - aggregate device intelligence
func (pb *PersistenceBridge) GetAggregateDevices() []Device {
	if !pb.enabled || pb.manager == nil {
		return nil
	}

	return pb.manager.GetAllDevices()
}

// GetDeviceHistory returns the scan history for a specific device
func (pb *PersistenceBridge) GetDeviceHistory(deviceID string) []ScanSession {
	if !pb.enabled || pb.manager == nil {
		return nil
	}

	var history []ScanSession

	// Get all sessions and filter for this device
	allSessions := pb.manager.GetRecentSessions(100) // Last 100 sessions

	for _, session := range allSessions {
		for _, result := range session.Results {
			if pb.generateDeviceID(result) == deviceID {
				history = append(history, session)
				break
			}
		}
	}

	return history
}

// GetStatistics returns database statistics
func (pb *PersistenceBridge) GetStatistics() *DatabaseStats {
	if !pb.enabled || pb.manager == nil {
		return nil
	}

	stats := pb.manager.GetStatistics()
	return &stats
}

// ExportToJSON exports all devices to JSON for external use
func (pb *PersistenceBridge) ExportToJSON() ([]byte, error) {
	if !pb.enabled || pb.manager == nil {
		return nil, fmt.Errorf("persistence not enabled")
	}

	// Get the database and marshal it to JSON
	database := pb.manager.GetDatabase()
	jsonData, err := json.MarshalIndent(database, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal database to JSON: %w", err)
	}

	return jsonData, nil
}

// Close properly shuts down the persistence system
func (pb *PersistenceBridge) Close() error {
	if !pb.enabled || pb.manager == nil {
		return nil
	}

	return pb.manager.Close()
}

// Internal helper methods

func (pb *PersistenceBridge) convertLegacyFingerprint(legacy LegacyFingerprint) DeviceFingerprint {
	return DeviceFingerprint{
		IPAddress:        legacy.IPAddress,
		MACAddress:       "", // Legacy fingerprint doesn't include MAC
		Hostname:         "", // We'll extract this from SNMPData if available
		Vendor:           legacy.Vendor,
		DeviceType:       legacy.DeviceType,
		Model:            legacy.Model,
		SerialNumber:     legacy.SerialNumber,
		OSVersion:        legacy.OSVersion,
		FirmwareVersion:  legacy.FirmwareVersion,
		HardwareRevision: "", // Not in legacy format
		SysObjectID:      legacy.SysObjectID,
		SysDescr:         legacy.SysDescr,
		SysContact:       "", // Extract from SNMPData if available
		SysLocation:      "", // Extract from SNMPData if available
		SysName:          pb.extractSysName(legacy.SNMPData),
		SNMPData:         legacy.SNMPData,
		ConfidenceScore:  legacy.ConfidenceScore,
		DetectionMethod:  legacy.DetectionMethod,
		ScanTimestamp:    time.Now(),
	}
}

func (pb *PersistenceBridge) extractSysName(snmpData map[string]string) string {
	// Common OIDs for system name
	sysNameOIDs := []string{
		"1.3.6.1.2.1.1.5.0", // Standard sysName
		"sysName",
		"System Name",
	}

	for _, oid := range sysNameOIDs {
		if value, exists := snmpData[oid]; exists && value != "" {
			return strings.TrimSpace(value)
		}
	}

	return ""
}

func (pb *PersistenceBridge) generateSessionID() string {
	timestamp := time.Now().Format("20060102_150405")
	hash := md5.Sum([]byte(timestamp + fmt.Sprintf("%d", time.Now().UnixNano())))
	return fmt.Sprintf("scan_%s_%x", timestamp, hash[:4])
}

func (pb *PersistenceBridge) generateDeviceID(fingerprint DeviceFingerprint) string {
	// First, try to get a meaningful hostname
	hostname := fingerprint.Hostname
	if hostname == "" || hostname == fingerprint.IPAddress {
		hostname = fingerprint.SysName
	}

	// Only use hostname for devices with UNIQUE, descriptive hostnames
	if hostname != "" && hostname != fingerprint.IPAddress {
		// Check for generic hostnames that shouldn't be used for consolidation
		genericHostnames := map[string]bool{
			"zt231":     true,
			"zt610":     true,
			"zt411":     true,
			"zd410":     true,
			"zd420":     true,
			"printer":   true,
			"ups":       true,
			"switch":    true,
			"router":    true,
			"device":    true,
			"unknown":   true,
			"localhost": true,
			"default":   true,
		}

		cleanHostname := strings.ToLower(strings.TrimSpace(hostname))

		// Don't use generic hostnames OR very short hostnames (likely generic)
		if !genericHostnames[cleanHostname] && len(cleanHostname) > 4 {
			// Use hostname for devices with unique, descriptive hostnames
			return fmt.Sprintf("host_%s", strings.ReplaceAll(cleanHostname, ".", "_"))
		}
	}

	// For everything else, use IP-based ID (this will be the majority of devices)
	return fmt.Sprintf("ip_%s", strings.ReplaceAll(fingerprint.IPAddress, ".", "_"))
}

func (pb *PersistenceBridge) processFingerprint(fingerprint DeviceFingerprint, sessionID string) {
	deviceID := pb.generateDeviceID(fingerprint)

	// Check if device already exists
	if existingDevice, exists := pb.manager.GetDevice(deviceID); exists {
		// Merge with existing device
		merged := pb.mergeDeviceData(*existingDevice, fingerprint, sessionID)
		pb.manager.AddDevice(merged)
	} else {
		// Create new device
		newDevice := pb.createNewDevice(deviceID, fingerprint, sessionID)
		pb.manager.AddDevice(newDevice)
	}
}

func (pb *PersistenceBridge) createNewDevice(deviceID string, fingerprint DeviceFingerprint, sessionID string) Device {
	now := time.Now()

	device := Device{
		ID:                 deviceID,
		PrimaryIP:          fingerprint.IPAddress,
		AllIPs:             []string{fingerprint.IPAddress},
		MACAddresses:       []string{},
		Hostname:           fingerprint.Hostname,
		Interfaces:         make(map[string]InterfaceInfo),
		Vendor:             fingerprint.Vendor,
		DeviceType:         fingerprint.DeviceType,
		Model:              fingerprint.Model,
		SerialNumber:       fingerprint.SerialNumber,
		OSVersion:          fingerprint.OSVersion,
		FirmwareVersion:    fingerprint.FirmwareVersion,
		HardwareRevision:   fingerprint.HardwareRevision,
		SysObjectID:        fingerprint.SysObjectID,
		SysDescr:           fingerprint.SysDescr,
		SysContact:         fingerprint.SysContact,
		SysLocation:        fingerprint.SysLocation,
		SysName:            fingerprint.SysName,
		FirstSeen:          now,
		LastSeen:           now,
		ScanCount:          1,
		LastScanID:         sessionID,
		IdentityMethod:     "basic",
		IdentityConfidence: IdentityWeak,
		SNMPDataByIP: map[string]map[string]string{
			fingerprint.IPAddress: fingerprint.SNMPData,
		},
		ConfidenceScore: fingerprint.ConfidenceScore,
		DetectionMethod: fingerprint.DetectionMethod,
		Tags:            []string{},
		CustomFields:    make(map[string]string),
	}

	// Add MAC address if available
	if fingerprint.MACAddress != "" {
		device.AddMAC(fingerprint.MACAddress)
	}

	// Create interface info
	interfaceKey := fmt.Sprintf("ip_%s", fingerprint.IPAddress)
	device.Interfaces[interfaceKey] = InterfaceInfo{
		Name:       fmt.Sprintf("Interface-%s", fingerprint.IPAddress),
		IPAddress:  fingerprint.IPAddress,
		MACAddress: fingerprint.MACAddress,
		Status:     "discovered",
		Type:       "data", // Default type
	}

	return device
}

func (pb *PersistenceBridge) mergeDeviceData(existing Device, fingerprint DeviceFingerprint, sessionID string) Device {
	merged := existing

	// Update last seen and scan count
	merged.LastSeen = time.Now()
	merged.ScanCount++
	merged.LastScanID = sessionID

	// Add new IP if not already present
	merged.AddIP(fingerprint.IPAddress)

	// Add MAC address if available
	if fingerprint.MACAddress != "" {
		merged.AddMAC(fingerprint.MACAddress)
	}

	// Initialize SNMP data by IP map if needed
	if merged.SNMPDataByIP == nil {
		merged.SNMPDataByIP = make(map[string]map[string]string)
	}

	// Store SNMP data for this IP
	merged.SNMPDataByIP[fingerprint.IPAddress] = fingerprint.SNMPData

	// Update device-level fields with most recent data
	if fingerprint.OSVersion != "" {
		merged.OSVersion = fingerprint.OSVersion
	}

	if fingerprint.Model != "" && (existing.Model == "" || len(fingerprint.Model) > len(existing.Model)) {
		merged.Model = fingerprint.Model
	}

	// Update hostname if new one is better
	if fingerprint.Hostname != "" && (existing.Hostname == "" || len(fingerprint.Hostname) > len(existing.Hostname)) {
		merged.Hostname = fingerprint.Hostname
	}

	// Add interface information
	if merged.Interfaces == nil {
		merged.Interfaces = make(map[string]InterfaceInfo)
	}

	interfaceKey := fmt.Sprintf("ip_%s", fingerprint.IPAddress)
	merged.Interfaces[interfaceKey] = InterfaceInfo{
		Name:       fmt.Sprintf("Interface-%s", fingerprint.IPAddress),
		IPAddress:  fingerprint.IPAddress,
		MACAddress: fingerprint.MACAddress,
		Status:     "discovered",
		Type:       pb.determineInterfaceType(fingerprint.IPAddress, merged.AllIPs),
	}

	// Increase confidence if consistent data
	if pb.isConsistentData(existing, fingerprint) {
		merged.ConfidenceScore = min(100, existing.ConfidenceScore+10)
	}

	return merged
}

func (pb *PersistenceBridge) determineInterfaceType(ip string, allIPs []string) string {
	// Simple interface type determination
	// This can be enhanced with more sophisticated logic

	if strings.Contains(ip, ".1.") || strings.HasSuffix(ip, ".1") {
		return "management"
	}

	return "data"
}

func (pb *PersistenceBridge) isConsistentData(existing Device, fingerprint DeviceFingerprint) bool {
	consistencyChecks := 0
	passedChecks := 0

	// Vendor consistency
	if existing.Vendor != "" && fingerprint.Vendor != "" {
		consistencyChecks++
		if existing.Vendor == fingerprint.Vendor {
			passedChecks++
		}
	}

	// Model consistency
	if existing.Model != "" && fingerprint.Model != "" {
		consistencyChecks++
		if existing.Model == fingerprint.Model {
			passedChecks++
		}
	}

	// sysObjectID consistency
	if existing.SysObjectID != "" && fingerprint.SysObjectID != "" {
		consistencyChecks++
		if existing.SysObjectID == fingerprint.SysObjectID {
			passedChecks++
		}
	}

	if consistencyChecks == 0 {
		return true // No conflicts
	}

	return float64(passedChecks)/float64(consistencyChecks) >= 0.7
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
