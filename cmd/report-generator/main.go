package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// DeviceDatabase represents the structure of your scanner_devices.json
type DeviceDatabase struct {
	Version      string            `json:"version"`
	LastUpdated  string            `json:"last_updated"`
	TotalDevices int               `json:"total_devices"`
	Devices      map[string]Device `json:"devices"`
	Sessions     []ScanSession     `json:"sessions,omitempty"`
	Statistics   *DatabaseStats    `json:"statistics,omitempty"`
	Config       *DatabaseConfig   `json:"config,omitempty"`
}

type Device struct {
	ID                 string                 `json:"id"`
	PrimaryIP          string                 `json:"primary_ip"`
	AllIPs             []string               `json:"all_ips"`
	MACAddresses       []string               `json:"mac_addresses"`
	Interfaces         map[string]Interface   `json:"interfaces"`
	Vendor             string                 `json:"vendor"`
	DeviceType         string                 `json:"device_type"`
	Model              string                 `json:"model,omitempty"`
	SerialNumber       string                 `json:"serial_number,omitempty"`
	SysDescr           string                 `json:"sys_descr,omitempty"`
	SysName            string                 `json:"sys_name,omitempty"`
	FirstSeen          string                 `json:"first_seen"`
	LastSeen           string                 `json:"last_seen"`
	ScanCount          int                    `json:"scan_count"`
	LastScanID         string                 `json:"last_scan_id"`
	IdentityMethod     string                 `json:"identity_method"`
	IdentityConfidence int                    `json:"identity_confidence"`
	SNMPDataByIP       map[string]interface{} `json:"snmp_data_by_ip"`
	ConfidenceScore    int                    `json:"confidence_score"`
	DetectionMethod    string                 `json:"detection_method"`
}

type Interface struct {
	Name      string `json:"name"`
	IPAddress string `json:"ip_address"`
	Status    string `json:"status"`
	Type      string `json:"type"`
}

type ScanSession struct {
	ID           string `json:"id"`
	Timestamp    string `json:"timestamp"`
	TargetIP     string `json:"target_ip"`
	ScanType     string `json:"scan_type"`
	DevicesFound int    `json:"devices_found"`
	NewDevices   int    `json:"new_devices"`
	Duration     string `json:"duration"`
}

type DatabaseStats struct {
	TotalDevices     int            `json:"total_devices"`
	TotalSessions    int            `json:"total_sessions"`
	VendorBreakdown  map[string]int `json:"vendor_breakdown"`
	TypeBreakdown    map[string]int `json:"type_breakdown"`
	LastScanDate     string         `json:"last_scan_date"`
	OldestDevice     string         `json:"oldest_device"`
	AvgConfidence    float64        `json:"avg_confidence"`
	DevicesPerSubnet map[string]int `json:"devices_per_subnet"`
	ErrorStats       map[string]int `json:"error_stats"`
}

type DatabaseConfig struct {
	MaxSessions     int   `json:"max_sessions"`
	MaxDevices      int   `json:"max_devices"`
	AutoCleanup     bool  `json:"auto_cleanup"`
	CleanupInterval int64 `json:"cleanup_interval"`
	BackupEnabled   bool  `json:"backup_enabled"`
	BackupCount     int   `json:"backup_count"`
	CompressBackups bool  `json:"compress_backups"`
}

type ReportGenerator struct {
	database DeviceDatabase
	filename string
}

// ReportStats holds calculated statistics
type ReportStats struct {
	TotalDevices           int
	KnownVendors           int
	UnknownDevices         int
	SNMPEnabledDevices     int
	DevicesByVendor        map[string]int
	DevicesByType          map[string]int
	DevicesBySubnet        map[string]int
	ConfidenceDistribution map[string]int
	ScanHistory            []ScanSummary
	TopDevicesByScans      []DeviceScanCount
}

type ScanSummary struct {
	Date         string
	DevicesFound int
	NewDevices   int
	Sessions     int
}

type DeviceScanCount struct {
	IP        string
	Hostname  string
	Vendor    string
	ScanCount int
}

func NewReportGenerator(filename string) (*ReportGenerator, error) {
	rg := &ReportGenerator{filename: filename}

	// Read and parse the JSON file
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading file %s: %w", filename, err)
	}

	err = json.Unmarshal(data, &rg.database)
	if err != nil {
		return nil, fmt.Errorf("error parsing JSON: %w", err)
	}

	return rg, nil
}

func (rg *ReportGenerator) GenerateStats() *ReportStats {
	stats := &ReportStats{
		DevicesByVendor:        make(map[string]int),
		DevicesByType:          make(map[string]int),
		DevicesBySubnet:        make(map[string]int),
		ConfidenceDistribution: make(map[string]int),
		TopDevicesByScans:      make([]DeviceScanCount, 0),
	}

	// Use deduplicated devices for statistics
	deviceMap := rg.deduplicateDevices()

	// Calculate device statistics
	for _, device := range deviceMap {
		stats.TotalDevices++

		// Vendor breakdown
		vendor := device.Vendor
		if vendor == "" || vendor == "unknown" {
			vendor = "unknown"
			stats.UnknownDevices++
		} else {
			stats.KnownVendors++
		}
		stats.DevicesByVendor[vendor]++

		// Device type breakdown
		deviceType := device.DeviceType
		if deviceType == "" {
			deviceType = "unknown"
		}
		stats.DevicesByType[deviceType]++

		// Check if device has SNMP data
		hasEnabledSNMP := false
		for _, snmpData := range device.SNMPDataByIP {
			if snmpMap, ok := snmpData.(map[string]interface{}); ok && len(snmpMap) > 0 {
				hasEnabledSNMP = true
				break
			}
		}
		if hasEnabledSNMP {
			stats.SNMPEnabledDevices++
		}

		// Subnet breakdown (extract /24 subnet)
		subnet := extractSubnet(device.PrimaryIP)
		stats.DevicesBySubnet[subnet]++

		// Confidence distribution
		confidenceRange := getConfidenceRange(device.ConfidenceScore)
		stats.ConfidenceDistribution[confidenceRange]++

		// Track devices by scan count
		hostname := device.SysName
		if hostname == "" {
			hostname = device.PrimaryIP
		}
		stats.TopDevicesByScans = append(stats.TopDevicesByScans, DeviceScanCount{
			IP:        device.PrimaryIP,
			Hostname:  hostname,
			Vendor:    vendor,
			ScanCount: device.ScanCount,
		})
	}

	// Sort devices by scan count
	sort.Slice(stats.TopDevicesByScans, func(i, j int) bool {
		return stats.TopDevicesByScans[i].ScanCount > stats.TopDevicesByScans[j].ScanCount
	})

	// Keep only top 20
	if len(stats.TopDevicesByScans) > 20 {
		stats.TopDevicesByScans = stats.TopDevicesByScans[:20]
	}

	return stats
}

func (rg *ReportGenerator) GenerateReport() {
	stats := rg.GenerateStats()

	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║                    NETWORK SCANNER REPORT                   ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()

	// Database Overview
	fmt.Printf("📊 DATABASE OVERVIEW\n")
	fmt.Printf("   File: %s\n", filepath.Base(rg.filename))
	fmt.Printf("   Last Updated: %s\n", formatTimestamp(rg.database.LastUpdated))
	fmt.Printf("   Database Version: %s\n", rg.database.Version)
	fmt.Println()

	// Device Summary
	fmt.Printf("🔍 DEVICE SUMMARY\n")
	fmt.Printf("   Total Devices: %d\n", stats.TotalDevices)
	fmt.Printf("   Known Vendors: %d (%.1f%%)\n", stats.KnownVendors,
		float64(stats.KnownVendors)/float64(stats.TotalDevices)*100)
	fmt.Printf("   Unknown Devices: %d (%.1f%%)\n", stats.UnknownDevices,
		float64(stats.UnknownDevices)/float64(stats.TotalDevices)*100)
	fmt.Printf("   SNMP Enabled: %d (%.1f%%)\n", stats.SNMPEnabledDevices,
		float64(stats.SNMPEnabledDevices)/float64(stats.TotalDevices)*100)
	fmt.Println()

	// Vendor Breakdown
	fmt.Printf("🏢 VENDOR BREAKDOWN\n")
	vendorList := make([]struct {
		name  string
		count int
	}, 0)
	for vendor, count := range stats.DevicesByVendor {
		vendorList = append(vendorList, struct {
			name  string
			count int
		}{vendor, count})
	}
	sort.Slice(vendorList, func(i, j int) bool {
		return vendorList[i].count > vendorList[j].count
	})
	for i, vendor := range vendorList {
		if i >= 10 {
			break
		} // Top 10 only
		percentage := float64(vendor.count) / float64(stats.TotalDevices) * 100
		fmt.Printf("   %-15s: %3d devices (%.1f%%)\n", vendor.name, vendor.count, percentage)
	}
	fmt.Println()

	// Device Type Breakdown
	fmt.Printf("🔧 DEVICE TYPE BREAKDOWN\n")
	typeList := make([]struct {
		name  string
		count int
	}, 0)
	for deviceType, count := range stats.DevicesByType {
		typeList = append(typeList, struct {
			name  string
			count int
		}{deviceType, count})
	}
	sort.Slice(typeList, func(i, j int) bool {
		return typeList[i].count > typeList[j].count
	})
	for i, deviceType := range typeList {
		if i >= 8 {
			break
		} // Top 8 only
		percentage := float64(deviceType.count) / float64(stats.TotalDevices) * 100
		fmt.Printf("   %-20s: %3d devices (%.1f%%)\n", deviceType.name, deviceType.count, percentage)
	}
	fmt.Println()

	// Subnet Distribution
	fmt.Printf("🌐 SUBNET DISTRIBUTION (Top 10)\n")
	subnetList := make([]struct {
		subnet string
		count  int
	}, 0)
	for subnet, count := range stats.DevicesBySubnet {
		subnetList = append(subnetList, struct {
			subnet string
			count  int
		}{subnet, count})
	}
	sort.Slice(subnetList, func(i, j int) bool {
		return subnetList[i].count > subnetList[j].count
	})
	for i, subnet := range subnetList {
		if i >= 10 {
			break
		} // Top 10 only
		percentage := float64(subnet.count) / float64(stats.TotalDevices) * 100
		fmt.Printf("   %-18s: %3d devices (%.1f%%)\n", subnet.subnet, subnet.count, percentage)
	}
	fmt.Println()

	// Confidence Distribution
	fmt.Printf("📈 CONFIDENCE DISTRIBUTION\n")
	for _, conf := range []string{"High (80-100%)", "Medium (50-79%)", "Low (0-49%)"} {
		count := stats.ConfidenceDistribution[conf]
		percentage := float64(count) / float64(stats.TotalDevices) * 100
		fmt.Printf("   %-15s: %3d devices (%.1f%%)\n", conf, count, percentage)
	}
	fmt.Println()

	// Most Frequently Scanned Devices
	fmt.Printf("🔄 MOST FREQUENTLY SCANNED DEVICES (Top 10)\n")
	for i, device := range stats.TopDevicesByScans {
		if i >= 10 {
			break
		}
		vendor := device.Vendor
		if vendor == "" || vendor == "unknown" {
			vendor = "unknown"
		}
		fmt.Printf("   %2d. %-15s %-25s %-10s (%d scans)\n",
			i+1, device.IP, truncateString(device.Hostname, 25), vendor, device.ScanCount)
	}
	fmt.Println()

	// Database Configuration (if available)
	if rg.database.Config != nil {
		fmt.Printf("⚙️  DATABASE CONFIGURATION\n")
		fmt.Printf("   Max Devices: %d\n", rg.database.Config.MaxDevices)
		fmt.Printf("   Max Sessions: %d\n", rg.database.Config.MaxSessions)
		fmt.Printf("   Auto Cleanup: %t\n", rg.database.Config.AutoCleanup)
		fmt.Printf("   Backups Enabled: %t\n", rg.database.Config.BackupEnabled)
		if rg.database.Config.BackupEnabled {
			fmt.Printf("   Backup Count: %d\n", rg.database.Config.BackupCount)
		}
		fmt.Println()
	}

	// Scan Performance Analysis
	rg.generateScanPerformanceReport()
}

func (rg *ReportGenerator) generateScanPerformanceReport() {
	fmt.Printf("🚀 SCAN PERFORMANCE & NETWORK ANALYSIS\n")

	// Analyze device distribution and network characteristics
	deviceMap := rg.deduplicateDevices()
	totalDevices := len(deviceMap)

	if totalDevices == 0 {
		fmt.Printf("   No device data available for analysis\n")
		fmt.Println()
		return
	}

	// Calculate time span of discoveries
	var earliestSeen, latestSeen time.Time
	scanCounts := make(map[string]int)

	for _, device := range deviceMap {
		// Track scan frequency
		scanCounts[device.PrimaryIP] = device.ScanCount

		// Parse timestamps
		if firstSeen := parseTimestamp(device.FirstSeen); !firstSeen.IsZero() {
			if earliestSeen.IsZero() || firstSeen.Before(earliestSeen) {
				earliestSeen = firstSeen
			}
		}

		if lastSeen := parseTimestamp(device.LastSeen); !lastSeen.IsZero() {
			if latestSeen.IsZero() || lastSeen.After(latestSeen) {
				latestSeen = lastSeen
			}
		}
	}

	// Calculate discovery period
	var discoveryPeriod time.Duration
	if !earliestSeen.IsZero() && !latestSeen.IsZero() {
		discoveryPeriod = latestSeen.Sub(earliestSeen)
		fmt.Printf("   Discovery Period: %s to %s\n",
			earliestSeen.Format("2006-01-02 15:04"),
			latestSeen.Format("2006-01-02 15:04"))
		fmt.Printf("   Total Discovery Timespan: %s\n", formatDuration(discoveryPeriod))
	}

	// Analyze network subnets and density
	subnetCounts := make(map[string]int)
	vendorCounts := make(map[string]int)
	typeCounts := make(map[string]int)
	snmpEnabledCount := 0
	knownVendorCount := 0

	for _, device := range deviceMap {
		subnet := extractSubnet(device.PrimaryIP)
		subnetCounts[subnet]++

		// Vendor analysis
		vendor := device.Vendor
		if vendor == "" || vendor == "unknown" {
			vendor = "unknown"
		} else {
			knownVendorCount++
		}
		vendorCounts[vendor]++

		// Device type analysis
		deviceType := device.DeviceType
		if deviceType == "" {
			deviceType = "unknown"
		}
		typeCounts[deviceType]++

		// SNMP analysis
		for _, snmpData := range device.SNMPDataByIP {
			if snmpMap, ok := snmpData.(map[string]interface{}); ok && len(snmpMap) > 0 {
				snmpEnabledCount++
				break
			}
		}
	}

	// Network density analysis
	totalSubnets := len(subnetCounts)
	avgDevicesPerSubnet := float64(totalDevices) / float64(totalSubnets)

	fmt.Printf("   Total Unique Devices: %d\n", totalDevices)
	fmt.Printf("   Active Subnets: %d\n", totalSubnets)
	fmt.Printf("   Network Density: %.1f devices per /24 subnet\n", avgDevicesPerSubnet)

	// Network efficiency classification
	var networkType string
	var efficiencyDescription string
	switch {
	case avgDevicesPerSubnet > 100:
		networkType = "Very Dense"
		efficiencyDescription = "High device concentration - conservative scanning recommended"
	case avgDevicesPerSubnet > 50:
		networkType = "Dense"
		efficiencyDescription = "High device count - moderate scanning speeds optimal"
	case avgDevicesPerSubnet > 20:
		networkType = "Moderate"
		efficiencyDescription = "Balanced density - standard scanning settings work well"
	case avgDevicesPerSubnet > 5:
		networkType = "Sparse"
		efficiencyDescription = "Low device density - aggressive scanning possible"
	default:
		networkType = "Very Sparse"
		efficiencyDescription = "Very low device density - maximum speed settings viable"
	}

	fmt.Printf("   Network Classification: %s\n", networkType)
	fmt.Printf("   Scanning Characteristics: %s\n", efficiencyDescription)

	// Find most/least populated subnets
	type subnetInfo struct {
		subnet string
		count  int
	}

	subnets := make([]subnetInfo, 0, len(subnetCounts))
	for subnet, count := range subnetCounts {
		subnets = append(subnets, subnetInfo{subnet, count})
	}

	sort.Slice(subnets, func(i, j int) bool {
		return subnets[i].count > subnets[j].count
	})

	if len(subnets) > 0 {
		fmt.Printf("   Most Populated: %s (%d devices)\n",
			subnets[0].subnet, subnets[0].count)

		if len(subnets) > 1 {
			fmt.Printf("   Least Populated: %s (%d device%s)\n",
				subnets[len(subnets)-1].subnet,
				subnets[len(subnets)-1].count,
				pluralize(subnets[len(subnets)-1].count))
		}
	}

	// Device intelligence analysis
	fmt.Printf("   SNMP Enabled Devices: %d (%.1f%%)\n",
		snmpEnabledCount, float64(snmpEnabledCount)/float64(totalDevices)*100)
	fmt.Printf("   Known Vendor Devices: %d (%.1f%%)\n",
		knownVendorCount, float64(knownVendorCount)/float64(totalDevices)*100)

	// Infrastructure analysis
	rg.analyzeInfrastructureTypes(typeCounts, totalDevices)

	// Scanning optimization recommendations
	rg.generateOptimizationRecommendations(avgDevicesPerSubnet, snmpEnabledCount, totalDevices)

	// Estimate scanning performance for different network sizes
	rg.estimateScanningPerformance(avgDevicesPerSubnet)

	fmt.Println()
}

func (rg *ReportGenerator) analyzeInfrastructureTypes(typeCounts map[string]int, totalDevices int) {
	// Analyze infrastructure composition
	infrastructureDevices := 0
	endUserDevices := 0
	managementDevices := 0

	for deviceType, count := range typeCounts {
		switch deviceType {
		case "switch", "router", "firewall", "wireless", "access_point":
			infrastructureDevices += count
		case "printer", "server", "workstation", "laptop":
			endUserDevices += count
		case "ups", "pdu", "monitor", "kvm":
			managementDevices += count
		}
	}

	fmt.Printf("   Infrastructure Breakdown:\n")
	fmt.Printf("     Network Infrastructure: %d devices (%.1f%%)\n",
		infrastructureDevices, float64(infrastructureDevices)/float64(totalDevices)*100)
	fmt.Printf("     End User Equipment: %d devices (%.1f%%)\n",
		endUserDevices, float64(endUserDevices)/float64(totalDevices)*100)
	fmt.Printf("     Management Systems: %d devices (%.1f%%)\n",
		managementDevices, float64(managementDevices)/float64(totalDevices)*100)
}

func (rg *ReportGenerator) generateOptimizationRecommendations(avgDensity float64, snmpDevices, totalDevices int) {
	fmt.Printf("   Optimization Recommendations:\n")

	// Concurrency recommendations
	var concurrency string
	var timeout string
	var rationale string

	snmpPercentage := float64(snmpDevices) / float64(totalDevices) * 100

	switch {
	case avgDensity > 50:
		concurrency = "25-50"
		timeout = "4-5 seconds"
		rationale = "Dense network - conservative approach to avoid overwhelming infrastructure"
	case avgDensity > 20:
		concurrency = "50-70"
		timeout = "4 seconds"
		rationale = "Moderate density - balanced speed and reliability (your optimal settings)"
	case avgDensity > 5:
		concurrency = "70-100"
		timeout = "3-4 seconds"
		rationale = "Sparse network - aggressive scanning for faster completion"
	default:
		concurrency = "100+"
		timeout = "2-3 seconds"
		rationale = "Very sparse - maximum speed settings viable"
	}

	fmt.Printf("     Recommended Concurrency: %s\n", concurrency)
	fmt.Printf("     Recommended Timeout: %s\n", timeout)
	fmt.Printf("     Rationale: %s\n", rationale)

	// SNMP-specific recommendations
	if snmpPercentage > 60 {
		fmt.Printf("     SNMP Strategy: Enable full fingerprinting (high SNMP adoption)\n")
	} else if snmpPercentage > 30 {
		fmt.Printf("     SNMP Strategy: Selective fingerprinting (moderate SNMP adoption)\n")
	} else {
		fmt.Printf("     SNMP Strategy: Basic discovery focus (low SNMP adoption)\n")
	}
}

func (rg *ReportGenerator) estimateScanningPerformance(avgDensity float64) {
	fmt.Printf("   Performance Estimates (based on your 16.9 IPs/sec optimal rate):\n")

	// Estimate scan times for different network sizes
	scanRates := []struct {
		network string
		hosts   int
		time    float64
	}{
		{"/24", 254, 254.0 / 16.9},
		{"/22", 1022, 1022.0 / 16.9},
		{"/20", 4094, 4094.0 / 16.9},
		{"/19", 8190, 8190.0 / 16.9},
		{"/18", 16382, 16382.0 / 16.9},
	}

	for _, estimate := range scanRates {
		minutes := estimate.time / 60
		expectedDevices := int(float64(estimate.hosts) * avgDensity / 254.0)

		if minutes < 1 {
			fmt.Printf("     %s subnet (%d hosts): %.0f seconds, ~%d devices expected\n",
				estimate.network, estimate.hosts, estimate.time, expectedDevices)
		} else if minutes < 60 {
			fmt.Printf("     %s subnet (%d hosts): %.1f minutes, ~%d devices expected\n",
				estimate.network, estimate.hosts, minutes, expectedDevices)
		} else {
			hours := minutes / 60
			fmt.Printf("     %s subnet (%d hosts): %.1f hours, ~%d devices expected\n",
				estimate.network, estimate.hosts, hours, expectedDevices)
		}
	}
}

func (rg *ReportGenerator) ExportToCSV(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("error creating CSV file: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	header := []string{
		"Primary_IP", "All_IPs", "Vendor", "Device_Type", "Model", "Serial_Number",
		"System_Name", "System_Description", "First_Seen", "Last_Seen",
		"Scan_Count", "Confidence_Score", "Detection_Method", "SNMP_Enabled",
		"MAC_Addresses", "Interface_Count",
	}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("error writing CSV header: %w", err)
	}

	// Deduplicate devices by system name
	deviceMap := rg.deduplicateDevices()

	// Write device data
	for _, device := range deviceMap {
		// Determine if SNMP is enabled
		snmpEnabled := "false"
		for _, snmpData := range device.SNMPDataByIP {
			if snmpMap, ok := snmpData.(map[string]interface{}); ok && len(snmpMap) > 0 {
				snmpEnabled = "true"
				break
			}
		}

		record := []string{
			device.PrimaryIP,
			strings.Join(device.AllIPs, ";"),
			device.Vendor,
			device.DeviceType,
			device.Model,
			device.SerialNumber,
			device.SysName,
			cleanString(device.SysDescr),
			formatTimestamp(device.FirstSeen),
			formatTimestamp(device.LastSeen),
			fmt.Sprintf("%d", device.ScanCount),
			fmt.Sprintf("%d", device.ConfidenceScore),
			device.DetectionMethod,
			snmpEnabled,
			strings.Join(device.MACAddresses, ";"),
			fmt.Sprintf("%d", len(device.Interfaces)),
		}

		if err := writer.Write(record); err != nil {
			return fmt.Errorf("error writing CSV record: %w", err)
		}
	}

	return nil
}

// deduplicateDevices removes duplicate devices based on system name
// For devices with the same system name, it keeps the one with the most recent scan
func (rg *ReportGenerator) deduplicateDevices() map[string]Device {
	deviceMap := make(map[string]Device)
	systemNameMap := make(map[string]Device)

	// First pass: group by system name
	for _, device := range rg.database.Devices {
		systemName := strings.TrimSpace(device.SysName)

		// If no system name, use IP as unique identifier
		if systemName == "" {
			deviceMap[device.PrimaryIP] = device
			continue
		}

		// Check if we already have a device with this system name
		if existingDevice, exists := systemNameMap[systemName]; exists {
			// Compare last seen dates to keep the most recent
			existing := parseTimestamp(existingDevice.LastSeen)
			current := parseTimestamp(device.LastSeen)

			if current.After(existing) {
				// Current device is more recent, replace it
				merged := rg.mergeDevices(existingDevice, device)
				systemNameMap[systemName] = merged
			} else {
				// Existing device is more recent, merge data into it
				merged := rg.mergeDevices(device, existingDevice)
				systemNameMap[systemName] = merged
			}
		} else {
			// First time seeing this system name
			systemNameMap[systemName] = device
		}
	}

	// Add deduplicated devices to the final map
	for _, device := range systemNameMap {
		deviceMap[device.PrimaryIP] = device
	}

	return deviceMap
}

// mergeDevices combines data from two devices representing the same system
func (rg *ReportGenerator) mergeDevices(older Device, newer Device) Device {
	merged := newer // Start with the newer device as base

	// Merge IP addresses
	allIPs := make(map[string]bool)
	for _, ip := range older.AllIPs {
		allIPs[ip] = true
	}
	for _, ip := range newer.AllIPs {
		allIPs[ip] = true
	}

	merged.AllIPs = make([]string, 0, len(allIPs))
	for ip := range allIPs {
		merged.AllIPs = append(merged.AllIPs, ip)
	}
	sort.Strings(merged.AllIPs)

	// Merge MAC addresses
	allMACs := make(map[string]bool)
	for _, mac := range older.MACAddresses {
		allMACs[mac] = true
	}
	for _, mac := range newer.MACAddresses {
		allMACs[mac] = true
	}

	merged.MACAddresses = make([]string, 0, len(allMACs))
	for mac := range allMACs {
		merged.MACAddresses = append(merged.MACAddresses, mac)
	}
	sort.Strings(merged.MACAddresses)

	// Merge interfaces
	for interfaceID, interfaceData := range older.Interfaces {
		if _, exists := merged.Interfaces[interfaceID]; !exists {
			merged.Interfaces[interfaceID] = interfaceData
		}
	}

	// Merge SNMP data
	for ip, snmpData := range older.SNMPDataByIP {
		if existingData, exists := merged.SNMPDataByIP[ip]; !exists || len(fmt.Sprintf("%v", existingData)) < len(fmt.Sprintf("%v", snmpData)) {
			merged.SNMPDataByIP[ip] = snmpData
		}
	}

	// Use the earlier first_seen date
	olderFirstSeen := parseTimestamp(older.FirstSeen)
	newerFirstSeen := parseTimestamp(merged.FirstSeen)
	if olderFirstSeen.Before(newerFirstSeen) {
		merged.FirstSeen = older.FirstSeen
	}

	// Combine scan counts
	merged.ScanCount = older.ScanCount + newer.ScanCount

	// Use higher confidence score
	if older.ConfidenceScore > merged.ConfidenceScore {
		merged.ConfidenceScore = older.ConfidenceScore
		merged.DetectionMethod = older.DetectionMethod
		merged.IdentityMethod = older.IdentityMethod
		merged.IdentityConfidence = older.IdentityConfidence
	}

	// Use non-empty values from either device
	if merged.Vendor == "" || merged.Vendor == "unknown" {
		if older.Vendor != "" && older.Vendor != "unknown" {
			merged.Vendor = older.Vendor
		}
	}

	if merged.DeviceType == "" || merged.DeviceType == "unknown" {
		if older.DeviceType != "" && older.DeviceType != "unknown" {
			merged.DeviceType = older.DeviceType
		}
	}

	if merged.Model == "" && older.Model != "" {
		merged.Model = older.Model
	}

	if merged.SerialNumber == "" && older.SerialNumber != "" {
		merged.SerialNumber = older.SerialNumber
	}

	return merged
}

// parseTimestamp safely parses timestamp strings
func parseTimestamp(timestamp string) time.Time {
	if timestamp == "" {
		return time.Time{}
	}

	layouts := []string{
		time.RFC3339,
		"2006-01-02T15:04:05.999999999-07:00",
		"2006-01-02T15:04:05-07:00",
		"2006-01-02 15:04:05",
	}

	for _, layout := range layouts {
		if t, err := time.Parse(layout, timestamp); err == nil {
			return t
		}
	}

	return time.Time{}
}

// Utility functions
func extractSubnet(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) >= 3 {
		return fmt.Sprintf("%s.%s.%s.0/24", parts[0], parts[1], parts[2])
	}
	return "unknown"
}

func getConfidenceRange(score int) string {
	if score >= 80 {
		return "High (80-100%)"
	} else if score >= 50 {
		return "Medium (50-79%)"
	} else {
		return "Low (0-49%)"
	}
}

func formatTimestamp(timestamp string) string {
	if timestamp == "" {
		return ""
	}

	// Try to parse the timestamp
	layouts := []string{
		time.RFC3339,
		"2006-01-02T15:04:05.999999999-07:00",
		"2006-01-02T15:04:05-07:00",
		"2006-01-02 15:04:05",
	}

	for _, layout := range layouts {
		if t, err := time.Parse(layout, timestamp); err == nil {
			return t.Format("2006-01-02 15:04:05")
		}
	}

	return timestamp // Return as-is if parsing fails
}

func cleanString(s string) string {
	// Remove newlines and carriage returns for CSV compatibility
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\"", "'")
	return strings.TrimSpace(s)
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func parseDuration(durationStr string) float64 {
	// Try to parse duration strings like "1s", "2.5s", "1m30s"
	if durationStr == "" {
		return 0
	}

	// Simple seconds parsing
	if strings.HasSuffix(durationStr, "s") {
		if seconds, err := fmt.Sscanf(durationStr, "%fs", new(float64)); err == nil && seconds == 1 {
			var f float64
			fmt.Sscanf(durationStr, "%fs", &f)
			return f
		}
	}

	// Try Go duration parsing
	if duration, err := time.ParseDuration(durationStr); err == nil {
		return duration.Seconds()
	}

	return 0
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.0f seconds", d.Seconds())
	} else if d < time.Hour {
		return fmt.Sprintf("%.1f minutes", d.Minutes())
	} else if d < 24*time.Hour {
		return fmt.Sprintf("%.1f hours", d.Hours())
	} else {
		days := int(d.Hours() / 24)
		return fmt.Sprintf("%d day%s", days, pluralize(days))
	}
}

func calculateAverage(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}

	sum := 0.0
	for _, value := range values {
		sum += value
	}
	return sum / float64(len(values))
}

func calculateMax(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}

	max := values[0]
	for _, value := range values {
		if value > max {
			max = value
		}
	}
	return max
}

func pluralize(count int) string {
	if count == 1 {
		return ""
	}
	return "s"
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s <scanner_devices.json> [export.csv]\n", os.Args[0])
		fmt.Println("\nExample:")
		fmt.Printf("  %s scanner_devices.json\n", os.Args[0])
		fmt.Printf("  %s scanner_devices.json devices_export.csv\n", os.Args[0])
		os.Exit(1)
	}

	jsonFile := os.Args[1]

	// Check if file exists
	if _, err := os.Stat(jsonFile); os.IsNotExist(err) {
		log.Fatalf("File does not exist: %s", jsonFile)
	}

	// Create report generator
	rg, err := NewReportGenerator(jsonFile)
	if err != nil {
		log.Fatalf("Error creating report generator: %v", err)
	}

	// Generate and display report
	rg.GenerateReport()

	// Export to CSV if filename provided
	if len(os.Args) >= 3 {
		csvFile := os.Args[2]
		fmt.Printf("📁 Exporting devices to CSV: %s\n", csvFile)

		if err := rg.ExportToCSV(csvFile); err != nil {
			log.Fatalf("Error exporting to CSV: %v", err)
		}

		// Calculate deduplicated count
		deduplicatedCount := len(rg.deduplicateDevices())

		fmt.Printf("✅ Successfully exported %d unique devices to %s\n",
			deduplicatedCount, csvFile)
		fmt.Printf("   (Deduplicated from %d total device entries)\n", rg.database.TotalDevices)
	} else {
		fmt.Println("💡 To export to CSV, run:")
		fmt.Printf("   %s %s devices_export.csv\n", os.Args[0], jsonFile)
	}
}
