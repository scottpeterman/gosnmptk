// pkg/persistence/models.go
package persistence

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"
)

// IdentityStrength represents how confident we are in device identification
type IdentityStrength int

const (
	IdentityWeak IdentityStrength = iota
	IdentityModerate
	IdentityStrong
	IdentityDefinitive
)

func (is IdentityStrength) String() string {
	switch is {
	case IdentityDefinitive:
		return "definitive"
	case IdentityStrong:
		return "strong"
	case IdentityModerate:
		return "moderate"
	case IdentityWeak:
		return "weak"
	default:
		return "unknown"
	}
}

// InterfaceInfo represents a network interface on a device
type InterfaceInfo struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	IPAddress   string `json:"ip_address,omitempty"`
	MACAddress  string `json:"mac_address,omitempty"`
	Status      string `json:"status,omitempty"`
	Type        string `json:"type,omitempty"` // management, data, point-to-point, vlan, loopback
	VLAN        string `json:"vlan,omitempty"`
	AdminStatus string `json:"admin_status,omitempty"`
	OperStatus  string `json:"oper_status,omitempty"`
	Speed       string `json:"speed,omitempty"`
	MTU         string `json:"mtu,omitempty"`
}

// Device represents a network device with support for multiple interfaces
type Device struct {
	// Identity
	ID           string   `json:"id"`            // Unique device identifier
	PrimaryIP    string   `json:"primary_ip"`    // Primary management IP
	AllIPs       []string `json:"all_ips"`       // All discovered IP addresses
	MACAddresses []string `json:"mac_addresses"` // All discovered MAC addresses
	Hostname     string   `json:"hostname,omitempty"`

	// Interface Information
	Interfaces map[string]InterfaceInfo `json:"interfaces,omitempty"`

	// Vendor Information
	Vendor       string `json:"vendor"`
	DeviceType   string `json:"device_type"`
	Model        string `json:"model,omitempty"`
	SerialNumber string `json:"serial_number,omitempty"`

	// Software/Firmware
	OSVersion       string `json:"os_version,omitempty"`
	FirmwareVersion string `json:"firmware_version,omitempty"`

	// Hardware Details
	HardwareRevision string `json:"hardware_revision,omitempty"`

	// SNMP Specific
	SysObjectID string `json:"sys_object_id,omitempty"`
	SysDescr    string `json:"sys_descr,omitempty"`
	SysContact  string `json:"sys_contact,omitempty"`
	SysLocation string `json:"sys_location,omitempty"`
	SysName     string `json:"sys_name,omitempty"`
	SysUptime   string `json:"sys_uptime,omitempty"`

	// Discovery Metadata
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	ScanCount  int       `json:"scan_count"`
	LastScanID string    `json:"last_scan_id"`

	// Identity Confidence
	IdentityMethod     string           `json:"identity_method"`
	IdentityConfidence IdentityStrength `json:"identity_confidence"`

	// Raw SNMP Data per IP
	SNMPDataByIP map[string]map[string]string `json:"snmp_data_by_ip"`

	// Confidence and Detection
	ConfidenceScore int    `json:"confidence_score"`
	DetectionMethod string `json:"detection_method"`

	// Tags and Classification
	Tags         []string          `json:"tags,omitempty"`
	CustomFields map[string]string `json:"custom_fields,omitempty"`
}

// ScanError represents an error that occurred during scanning
type ScanError struct {
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
	IP        string    `json:"ip,omitempty"`
	OID       string    `json:"oid,omitempty"`
	ErrorType string    `json:"error_type,omitempty"`
}

// ScanSession represents a single scanning session
type ScanSession struct {
	ID             string                 `json:"id"`
	Timestamp      time.Time              `json:"timestamp"`
	TargetIP       string                 `json:"target_ip"`
	ScanType       string                 `json:"scan_type"` // fingerprint, discovery, bulk_test
	Duration       time.Duration          `json:"duration"`
	DevicesFound   int                    `json:"devices_found"`
	NewDevices     int                    `json:"new_devices"`     // Devices found for first time
	UpdatedDevices int                    `json:"updated_devices"` // Existing devices with new data
	Results        []DeviceFingerprint    `json:"results"`
	Errors         []ScanError            `json:"errors,omitempty"`
	Config         map[string]interface{} `json:"config,omitempty"` // Scan configuration used
	Notes          string                 `json:"notes,omitempty"`
}

// DatabaseStats provides statistics about the device database
type DatabaseStats struct {
	TotalDevices     int            `json:"total_devices"`
	TotalSessions    int            `json:"total_sessions"`
	VendorBreakdown  map[string]int `json:"vendor_breakdown"`
	TypeBreakdown    map[string]int `json:"type_breakdown"`
	LastScanDate     time.Time      `json:"last_scan_date"`
	OldestDevice     time.Time      `json:"oldest_device"`
	AvgConfidence    float64        `json:"avg_confidence"`
	DevicesPerSubnet map[string]int `json:"devices_per_subnet"`
	ErrorStats       map[string]int `json:"error_stats"`
}

// DeviceDatabase represents the aggregate collection of all discovered devices
type DeviceDatabase struct {
	Version      string                 `json:"version"`
	LastUpdated  time.Time              `json:"last_updated"`
	TotalDevices int                    `json:"total_devices"`
	Devices      map[string]Device      `json:"devices"` // Key: Device ID
	Sessions     []ScanSession          `json:"sessions"`
	Statistics   DatabaseStats          `json:"statistics"`
	Config       DatabaseConfig         `json:"config"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// DatabaseConfig holds configuration for the database
type DatabaseConfig struct {
	MaxSessions     int           `json:"max_sessions"`     // Maximum sessions to keep
	MaxDevices      int           `json:"max_devices"`      // Maximum devices to keep in memory
	AutoCleanup     bool          `json:"auto_cleanup"`     // Automatically cleanup old data
	CleanupInterval time.Duration `json:"cleanup_interval"` // How often to cleanup
	BackupEnabled   bool          `json:"backup_enabled"`   // Enable automatic backups
	BackupCount     int           `json:"backup_count"`     // Number of backups to keep
	CompressBackups bool          `json:"compress_backups"` // Compress backup files
}

// DeviceFingerprint represents the result of scanning a single IP
// This maintains compatibility with existing fingerprinting code
type DeviceFingerprint struct {
	IPAddress        string            `json:"ip_address"`
	MACAddress       string            `json:"mac_address,omitempty"`
	Hostname         string            `json:"hostname,omitempty"`
	Vendor           string            `json:"vendor"`
	DeviceType       string            `json:"device_type"`
	Model            string            `json:"model,omitempty"`
	SerialNumber     string            `json:"serial_number,omitempty"`
	OSVersion        string            `json:"os_version,omitempty"`
	FirmwareVersion  string            `json:"firmware_version,omitempty"`
	HardwareRevision string            `json:"hardware_revision,omitempty"`
	SysObjectID      string            `json:"sys_object_id,omitempty"`
	SysDescr         string            `json:"sys_descr,omitempty"`
	SysContact       string            `json:"sys_contact,omitempty"`
	SysLocation      string            `json:"sys_location,omitempty"`
	SysName          string            `json:"sys_name,omitempty"`
	SNMPData         map[string]string `json:"snmp_data"`
	ConfidenceScore  int               `json:"confidence_score"`
	DetectionMethod  string            `json:"detection_method"`
	ScanTimestamp    time.Time         `json:"scan_timestamp"`
}

// Helper methods for Device

// AddIP adds a new IP address to the device if not already present
func (d *Device) AddIP(ip string) bool {
	for _, existingIP := range d.AllIPs {
		if existingIP == ip {
			return false // Already exists
		}
	}
	d.AllIPs = append(d.AllIPs, ip)
	return true
}

// AddMAC adds a new MAC address to the device if not already present
func (d *Device) AddMAC(mac string) bool {
	mac = strings.ToLower(strings.TrimSpace(mac))
	if mac == "" {
		return false
	}

	for _, existingMAC := range d.MACAddresses {
		if existingMAC == mac {
			return false // Already exists
		}
	}
	d.MACAddresses = append(d.MACAddresses, mac)
	return true
}

// HasIP checks if the device has a specific IP address
func (d *Device) HasIP(ip string) bool {
	for _, existingIP := range d.AllIPs {
		if existingIP == ip {
			return true
		}
	}
	return false
}

// GetSubnet returns the primary subnet this device belongs to
func (d *Device) GetSubnet() string {
	if d.PrimaryIP == "" {
		return ""
	}

	ip := net.ParseIP(d.PrimaryIP)
	if ip == nil {
		return ""
	}

	// Return /24 subnet
	ipv4 := ip.To4()
	if ipv4 != nil {
		return fmt.Sprintf("%d.%d.%d.0/24", ipv4[0], ipv4[1], ipv4[2])
	}

	return ""
}

// IsManagementIP determines if an IP is likely a management interface
func (d *Device) IsManagementIP(ip string) bool {
	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		return false
	}

	ipBytes := ipAddr.To4()
	if ipBytes == nil {
		return false
	}

	// Common management IP patterns
	// .1 addresses
	if ipBytes[3] == 1 {
		return true
	}

	// Management VLANs
	managementVLANs := []byte{1, 99, 100, 254}
	for _, vlan := range managementVLANs {
		if ipBytes[2] == vlan {
			return true
		}
	}

	return false
}

// GetDisplayName returns the best available name for the device
func (d *Device) GetDisplayName() string {
	if d.Hostname != "" {
		return d.Hostname
	}
	if d.SysName != "" {
		return d.SysName
	}
	return d.PrimaryIP
}

// UpdateStatistics recalculates database statistics
func (db *DeviceDatabase) UpdateStatistics() {
	stats := DatabaseStats{
		TotalDevices:     len(db.Devices),
		TotalSessions:    len(db.Sessions),
		VendorBreakdown:  make(map[string]int),
		TypeBreakdown:    make(map[string]int),
		DevicesPerSubnet: make(map[string]int),
		ErrorStats:       make(map[string]int),
	}

	var totalConfidence int
	var oldestTime time.Time
	var newestScan time.Time

	// Analyze devices
	for _, device := range db.Devices {
		// Vendor breakdown
		if device.Vendor != "" {
			stats.VendorBreakdown[device.Vendor]++
		}

		// Type breakdown
		if device.DeviceType != "" {
			stats.TypeBreakdown[device.DeviceType]++
		}

		// Subnet breakdown
		subnet := device.GetSubnet()
		if subnet != "" {
			stats.DevicesPerSubnet[subnet]++
		}

		// Confidence average
		totalConfidence += device.ConfidenceScore

		// Age tracking
		if oldestTime.IsZero() || device.FirstSeen.Before(oldestTime) {
			oldestTime = device.FirstSeen
		}

		if device.LastSeen.After(newestScan) {
			newestScan = device.LastSeen
		}
	}

	// Calculate averages
	if len(db.Devices) > 0 {
		stats.AvgConfidence = float64(totalConfidence) / float64(len(db.Devices))
	}

	stats.OldestDevice = oldestTime
	stats.LastScanDate = newestScan

	// Analyze session errors
	for _, session := range db.Sessions {
		for _, err := range session.Errors {
			if err.ErrorType != "" {
				stats.ErrorStats[err.ErrorType]++
			} else {
				stats.ErrorStats["general"]++
			}
		}
	}

	db.Statistics = stats
}

// Helper function to create a new empty database
func NewDeviceDatabase() *DeviceDatabase {
	return &DeviceDatabase{
		Version:      "1.0.0",
		LastUpdated:  time.Now(),
		TotalDevices: 0,
		Devices:      make(map[string]Device),
		Sessions:     make([]ScanSession, 0),
		Statistics: DatabaseStats{
			VendorBreakdown:  make(map[string]int),
			TypeBreakdown:    make(map[string]int),
			DevicesPerSubnet: make(map[string]int),
			ErrorStats:       make(map[string]int),
		},
		Config: DatabaseConfig{
			MaxSessions:     100,
			MaxDevices:      10000,
			AutoCleanup:     true,
			CleanupInterval: 24 * time.Hour,
			BackupEnabled:   true,
			BackupCount:     5,
			CompressBackups: false,
		},
		Metadata: make(map[string]interface{}),
	}
}

// JSON marshaling helpers for time.Duration
func (ss *ScanSession) MarshalJSON() ([]byte, error) {
	type Alias ScanSession
	return json.Marshal(&struct {
		*Alias
		Duration string `json:"duration"`
	}{
		Alias:    (*Alias)(ss),
		Duration: ss.Duration.String(),
	})
}

func (ss *ScanSession) UnmarshalJSON(data []byte) error {
	type Alias ScanSession
	aux := &struct {
		*Alias
		Duration string `json:"duration"`
	}{
		Alias: (*Alias)(ss),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	duration, err := time.ParseDuration(aux.Duration)
	if err != nil {
		return err
	}

	ss.Duration = duration
	return nil
}
