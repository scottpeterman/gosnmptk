package main

// Add these imports to the top of main.go
import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/scottpeterman/gosnmptk/pkg/fingerprint"
	"github.com/scottpeterman/gosnmptk/pkg/persistence"
	"github.com/scottpeterman/gosnmptk/pkg/snmp"
)

// VendorDetectionLogger handles vendor detection logging
type VendorDetectionLogger struct {
	enabled bool
	verbose bool
	logFile *os.File
	logger  *log.Logger
}

type TCPPortChecker struct {
	timeout time.Duration
	ports   []int
}

// SNMPVersionResult represents the result of SNMP version testing
type SNMPVersionResult struct {
	Success      bool
	Version      string
	Community    string
	Username     string
	SysDescr     string
	SysName      string
	Client       *snmp.Client
	ErrorMessage string
}

// CLIConfig represents the complete configuration for the CLI scanner
type CLIConfig struct {
	// Operation mode
	Mode string // scan, fingerprint, test, discover, query

	// Network targets
	Target    string   // Single IP or CIDR
	Targets   []string // Multiple targets from file
	PortRange string   // Port range for discovery

	// SNMP Configuration
	Community    string
	Username     string
	AuthProtocol string
	AuthKey      string
	PrivProtocol string
	PrivKey      string
	Version      int
	Timeout      time.Duration
	Retries      int

	// Scanning options
	Concurrency int
	Fast        bool
	Verbose     bool
	Quiet       bool

	// Fingerprinting options
	FingerprintType string // basic, full, vendor-specific
	VendorFilter    string // Filter by specific vendor
	ConfigPath      string // Path to vendor fingerprint YAML config

	// Output options
	OutputFormat string // json, csv, table, simple
	OutputFile   string
	ShowDetails  bool

	// Persistence options
	DatabasePath   string
	EnableDatabase bool

	// Discovery options
	PingTimeout   time.Duration
	PortTimeout   time.Duration
	DiscoveryScan bool

	// Vendor debugging options (NEW - add these fields to your existing CLIConfig)
	VendorDebug        bool   // Enable vendor detection debugging
	VendorLogFile      string // Path to vendor detection log file
	TCPCheckTimeout    time.Duration
	TCPCheckPorts      []int
	SkipTCPCheck       bool
	EnableSNMPFallback bool
	Communities        []string
}

// NewVendorDetectionLogger creates a new vendor detection logger
func NewVendorDetectionLogger(enabled, verbose bool, logPath string) *VendorDetectionLogger {
	vdl := &VendorDetectionLogger{
		enabled: enabled,
		verbose: verbose,
	}

	if enabled && logPath != "" {
		if file, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666); err == nil {
			vdl.logFile = file
			vdl.logger = log.New(file, "[VENDOR] ", log.LstdFlags)
		}
	}

	if vdl.logger == nil {
		vdl.logger = log.New(os.Stdout, "[VENDOR] ", log.LstdFlags)
	}

	return vdl
}

// Close closes the log file if open
func (vdl *VendorDetectionLogger) Close() {
	if vdl.logFile != nil {
		vdl.logFile.Close()
	}
}

// LogDetectionStart logs the start of vendor detection
func (vdl *VendorDetectionLogger) LogDetectionStart(ip, sysDescr, sysObjectID string) {
	if !vdl.enabled {
		return
	}

	vdl.logger.Printf("DETECTION_START ip=%s sysDescr='%s' sysObjectID='%s'",
		ip, vdl.truncate(sysDescr, 100), sysObjectID)
}

// LogVendorTest logs testing of a specific vendor
func (vdl *VendorDetectionLogger) LogVendorTest(vendor string, priority int, patterns, exclusions []string) {
	if !vdl.enabled || !vdl.verbose {
		return
	}

	vdl.logger.Printf("VENDOR_TEST vendor=%s priority=%d patterns=%v exclusions=%v",
		vendor, priority, patterns, exclusions)
}

// LogPatternMatch logs when a pattern matches
func (vdl *VendorDetectionLogger) LogPatternMatch(vendor, pattern, text string, matched bool, excluded bool) {
	if !vdl.enabled {
		return
	}

	status := "NO_MATCH"
	if excluded {
		status = "EXCLUDED"
	} else if matched {
		status = "MATCHED"
	}

	vdl.logger.Printf("PATTERN_TEST vendor=%s pattern='%s' status=%s text='%s'",
		vendor, pattern, status, vdl.truncate(text, 50))
}

// LogDetectionResult logs the final detection result
func (vdl *VendorDetectionLogger) LogDetectionResult(ip, vendor, confidence, method string) {
	if !vdl.enabled {
		return
	}

	vdl.logger.Printf("DETECTION_RESULT ip=%s vendor=%s confidence=%s method=%s",
		ip, vendor, confidence, method)
}

// LogError logs detection errors
func (vdl *VendorDetectionLogger) LogError(ip, error string) {
	if !vdl.enabled {
		return
	}

	vdl.logger.Printf("DETECTION_ERROR ip=%s error='%s'", ip, error)
}

// LogYAMLConfigStatus logs YAML configuration status
func (vdl *VendorDetectionLogger) LogYAMLConfigStatus(loaded bool, vendorCount int, priorityOrder []string) {
	if !vdl.enabled {
		return
	}

	vdl.logger.Printf("YAML_CONFIG loaded=%t vendors=%d priority_order=%v",
		loaded, vendorCount, priorityOrder)
}

// truncate truncates strings for cleaner logging
func (vdl *VendorDetectionLogger) truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

const (
	Version = "1.0.0"
	Banner  = `
   ▄████  ▒█████       ██████  ███▄    █  ███▄ ▄███▓ ██▓███      ▄████▄   ██▓     ██▓
  ██▒ ▀█▒▒██▒  ██▒   ▒██    ▒  ██ ▀█   █ ▓██▒▀█▀ ██▒▓██░  ██▒   ▒██▀ ▀█  ▓██▒    ▓██▒
 ▒██░▄▄▄░▒██░  ██▒   ░ ▓██▄   ▓██  ▀█ ██▒▓██    ▓██░▓██░ ██▓▒   ▒▓█    ▄ ▒██░    ▒██▒
 ░▓█  ██▓▒██   ██░     ▒   ██▒▓██▒  ▐▌██▒▒██    ▒██ ▒██▄█▓▒ ▒   ▒▓▓▄ ▄██▒▒██░    ░██░
 ░▒▓███▀▒░ ████▓▒░   ▒██████▒▒▒██░   ▓██░▒██▒   ░██▒▒██▒ ░  ░   ▒ ▓███▀ ░░██████▒░██░
  ░▒   ▒ ░ ▒░▒░▒░    ▒ ▒▓▒ ▒ ░░ ▒░   ▒ ▒ ░ ▒░   ░  ░▒▓▒░ ░  ░   ░ ░▒ ▒  ░░ ▒░▓  ░░▓  
   ░   ░   ░ ▒ ▒░    ░ ░▒  ░ ░░ ░░   ░ ▒░░  ░      ░░▒ ░          ░  ▒   ░ ░ ▒  ░ ▒ ░
 ░ ░   ░ ░ ░ ░ ▒     ░  ░  ░     ░   ░ ░ ░      ░   ░░          ░          ░ ░    ▒ ░
       ░     ░ ░           ░           ░        ░               ░ ░          ░  ░ ░  
                                                               ░                    
 Go SNMP Toolkit CLI - Network Discovery & Vendor Fingerprinting v%s
`
)

// YAML Configuration Structures
type VendorConfig struct {
	DisplayName         string              `yaml:"display_name"`
	EnterpriseOID       string              `yaml:"enterprise_oid"`
	DetectionPatterns   []string            `yaml:"detection_patterns"`
	OIDPatterns         []string            `yaml:"oid_patterns"`
	DeviceTypes         []string            `yaml:"device_types"`
	ExclusionPatterns   []string            `yaml:"exclusion_patterns"`
	DeviceTypeOverrides map[string][]string `yaml:"device_type_overrides"`
	FingerprintOIDs     []FingerprintOID    `yaml:"fingerprint_oids"`

	ModelExtraction    []ExtractionRule `yaml:"model_extraction"`
	SerialExtraction   []ExtractionRule `yaml:"serial_extraction"`
	FirmwareExtraction []ExtractionRule `yaml:"firmware_extraction"`
}
type ExtractionRule struct {
	Regex        string   `yaml:"regex"`
	Priority     int      `yaml:"priority"`
	CaptureGroup int      `yaml:"capture_group"`
	DeviceTypes  []string `yaml:"device_types"`
	Description  string   `yaml:"description"`
}
type FingerprintOID struct {
	Name        string   `yaml:"name"`
	OID         string   `yaml:"oid"`
	Priority    int      `yaml:"priority"`
	Description string   `yaml:"description"`
	DeviceTypes []string `yaml:"device_types"`

	Definitive     bool     `yaml:"definitive,omitempty"`
	ExpectedValues []string `yaml:"expected_values,omitempty"`
}

type DetectionRules struct {
	PriorityOrder    []string          `yaml:"priority_order"`
	ConfidenceLevels map[string]string `yaml:"confidence_levels"`
}

type VendorFingerprintConfig struct {
	Version        string                  `yaml:"version"`
	Metadata       map[string]interface{}  `yaml:"metadata"`
	CommonOIDs     map[string]string       `yaml:"common_oids"`
	GenericOIDs    []FingerprintOID        `yaml:"generic_oids"`
	Vendors        map[string]VendorConfig `yaml:"vendors"`
	DetectionRules DetectionRules          `yaml:"detection_rules"`
	Scanning       map[string]interface{}  `yaml:"scanning"`
}

// ScanResult represents a CLI scan result
type CLIScanResult struct {
	IP               string            `json:"ip"`
	Hostname         string            `json:"hostname,omitempty"`
	Responding       bool              `json:"responding"`
	RTT              time.Duration     `json:"rtt,omitempty"`
	SNMPReady        bool              `json:"snmp_ready"`
	SNMPVersion      string            `json:"snmp_version,omitempty"`
	SNMPCommunity    string            `json:"snmp_community,omitempty"`
	SystemDescr      string            `json:"system_descr,omitempty"`
	SystemName       string            `json:"system_name,omitempty"`
	DetectedVendor   string            `json:"detected_vendor,omitempty"`
	VendorConfidence string            `json:"vendor_confidence,omitempty"`
	VendorMethod     string            `json:"vendor_method,omitempty"`
	DeviceType       string            `json:"device_type,omitempty"`
	Model            string            `json:"model,omitempty"`
	SerialNumber     string            `json:"serial_number,omitempty"`
	FirmwareVersion  string            `json:"firmware_version,omitempty"`
	VendorData       map[string]string `json:"vendor_data,omitempty"`
	Error            string            `json:"error,omitempty"`
	ScanTime         time.Time         `json:"scan_time"`

	// Enhanced fingerprinting fields
	FingerprintPerformed bool   `json:"fingerprint_performed"`
	FingerprintError     string `json:"fingerprint_error,omitempty"`
	vendorLogger         *VendorDetectionLogger
	TCPResponsive        bool     `json:"tcp_responsive"`
	TCPCheckPorts        []int    `json:"tcp_check_ports,omitempty"`
	SNMPVersionAttempted []string `json:"snmp_version_attempted,omitempty"`
	SNMPVersionUsed      string   `json:"snmp_version_used,omitempty"`
	OIDsCollected        int      `json:"oids_collected"`
	OIDsSuccessful       []string `json:"oids_successful,omitempty"`
	OIDsFailed           []string `json:"oids_failed,omitempty"`
}

// CLI Scanner
type CLIScanner struct {
	config  CLIConfig
	results []CLIScanResult
	mu      sync.RWMutex

	// Progress tracking
	current   int64
	total     int64
	found     int64
	snmpReady int64
	startTime time.Time

	// Cancellation
	ctx    context.Context
	cancel context.CancelFunc

	// Persistence
	persistenceBridge *persistence.PersistenceBridge

	// Vendor configuration
	vendorConfig   *VendorFingerprintConfig
	vendorLogger   *VendorDetectionLogger
	tcpChecker     *TCPPortChecker
	oidCollector   *YAMLOIDCollector
	fieldExtractor *SmartFieldExtractor
}

func (s *CLIScanner) extractSysObjectID(result CLIScanResult) string {
	// Look for sysObjectID in vendor data
	if result.VendorData != nil {
		for key, value := range result.VendorData {
			if strings.Contains(strings.ToLower(key), "object") ||
				strings.Contains(strings.ToLower(key), "oid") ||
				key == "1.3.6.1.2.1.1.2.0" { // Standard sysObjectID OID
				return value
			}
		}
	}
	return ""
}
func main() {
	config := parseFlags()

	if config.Mode == "" {
		printUsage()
		os.Exit(1)
	}

	// Create and configure scanner
	scanner := NewCLIScanner(config)
	defer scanner.vendorLogger.Close() // Clean up logging

	if !config.Quiet {
		fmt.Printf(Banner, Version)
		fmt.Println()
	}

	switch config.Mode {
	case "scan":
		scanner.runNetworkScan()
	case "fingerprint":
		scanner.runFingerprinting()
	case "test":
		scanner.runSNMPTest()
	case "discover":
		scanner.runDiscovery()
	case "query":
		scanner.runOIDQuery()
	default:
		fmt.Printf("Unknown mode: %s\n", config.Mode)
		printUsage()
		os.Exit(1)
	}
}

// ADD these lines at the beginning of your existing NewCLIScanner function:

func NewTCPPortChecker(timeout time.Duration, ports []int) *TCPPortChecker {
	if len(ports) == 0 {
		// Default ports including printer and common service ports
		ports = []int{20, 21, 22, 25, 53, 80, 161, 443, 515, 631, 993, 995, 9100}
	}
	return &TCPPortChecker{
		timeout: timeout,
		ports:   ports,
	}
}
func NewCLIScanner(config CLIConfig) *CLIScanner {
	ctx, cancel := context.WithCancel(context.Background())

	// Create vendor detection logger
	vendorLogEnabled := config.Verbose || os.Getenv("VENDOR_DEBUG") == "1"
	vendorLogPath := os.Getenv("VENDOR_LOG_FILE")

	scanner := &CLIScanner{
		config:       config,
		results:      make([]CLIScanResult, 0),
		ctx:          ctx,
		cancel:       cancel,
		vendorLogger: NewVendorDetectionLogger(vendorLogEnabled, config.Verbose, vendorLogPath),
		// NEW: Initialize enhanced components
		tcpChecker:     NewTCPPortChecker(config.TCPCheckTimeout, config.TCPCheckPorts),
		fieldExtractor: NewSmartFieldExtractor(nil), // Will be set after config load
	}

	// Load vendor configuration
	if err := scanner.loadVendorConfig(); err != nil {
		log.Printf("Warning: Failed to load vendor config: %v", err)
		scanner.vendorLogger.LogError("system", fmt.Sprintf("Failed to load vendor config: %v", err))
	} else {
		if scanner.vendorConfig != nil {
			scanner.vendorLogger.LogYAMLConfigStatus(
				true,
				len(scanner.vendorConfig.Vendors),
				scanner.vendorConfig.DetectionRules.PriorityOrder,
			)
			// Initialize field extractor with config
			scanner.fieldExtractor = NewSmartFieldExtractor(scanner.vendorConfig)
		} else {
			scanner.vendorLogger.LogYAMLConfigStatus(false, 0, nil)
		}
	}

	return scanner
}

func (s *CLIScanner) loadVendorConfig() error {
	// Try multiple paths for the config file
	configPaths := []string{
		s.config.ConfigPath,                 // User specified
		"./vendor_fingerprints.yaml",        // Current directory
		"./config/vendor_fingerprints.yaml", // Config subdirectory
		filepath.Join(os.Getenv("HOME"), ".gosnmp", "vendor_fingerprints.yaml"), // User home
		"/etc/gosnmp/vendor_fingerprints.yaml",                                  // System config
	}

	var configData []byte
	var err error
	var usedPath string

	for _, path := range configPaths {
		if path == "" {
			continue
		}

		configData, err = os.ReadFile(path)
		if err == nil {
			usedPath = path
			break
		}
	}

	if err != nil {
		if !s.config.Quiet {
			fmt.Printf("⚠️  Vendor fingerprint config not found, using built-in patterns\n")
		}
		return nil // Don't fail, just use fallback detection
	}

	config := &VendorFingerprintConfig{}
	if err := yaml.Unmarshal(configData, config); err != nil {
		if !s.config.Quiet {
			fmt.Printf("⚠️  Failed to parse vendor config: %v, using built-in patterns\n", err)
		}
		return nil // Don't fail, just use fallback detection
	}

	s.vendorConfig = config

	if !s.config.Quiet {
		fmt.Printf("📋 Loaded vendor config from: %s (%d vendors)\n", usedPath, len(config.Vendors))
	}

	return nil
}

// Complete parseFlags function with all Python-style enhancements
func parseFlags() CLIConfig {
	var config CLIConfig

	// Operation modes
	flag.StringVar(&config.Mode, "mode", "", "Operation mode: scan, fingerprint, test, discover, query")

	// Network targets
	flag.StringVar(&config.Target, "target", "", "Target IP address or CIDR (e.g., 192.168.1.1 or 192.168.1.0/24)")
	targetsFile := flag.String("targets-file", "", "File containing list of targets")
	flag.StringVar(&config.PortRange, "ports", "161", "Port range for discovery")

	// SNMP Configuration
	communities := flag.String("communities", "public,private", "SNMP communities (comma-separated)")
	flag.StringVar(&config.Username, "username", "", "SNMPv3 username")
	flag.StringVar(&config.AuthProtocol, "auth-protocol", "SHA", "SNMPv3 auth protocol")
	flag.StringVar(&config.AuthKey, "auth-key", "", "SNMPv3 authentication key")
	flag.StringVar(&config.PrivProtocol, "priv-protocol", "AES128", "SNMPv3 privacy protocol")
	flag.StringVar(&config.PrivKey, "priv-key", "", "SNMPv3 privacy key")
	flag.IntVar(&config.Version, "snmp-version", 2, "SNMP version (1,2,3)")
	timeout := flag.Duration("timeout", 2*time.Second, "SNMP timeout")
	flag.IntVar(&config.Retries, "retries", 1, "SNMP retries")

	// Scanning options
	flag.IntVar(&config.Concurrency, "concurrency", 50, "Max concurrent operations")
	flag.BoolVar(&config.Fast, "fast", false, "Fast mode (optimized timeouts, TCP ports, concurrency)")
	flag.BoolVar(&config.Verbose, "verbose", false, "Verbose output")
	flag.BoolVar(&config.Quiet, "quiet", false, "Quiet mode")

	// Fingerprinting options
	flag.StringVar(&config.FingerprintType, "fingerprint-type", "basic", "Fingerprint type: basic, full, auto")
	flag.StringVar(&config.VendorFilter, "vendor", "", "Filter by vendor")
	flag.StringVar(&config.ConfigPath, "config", "", "Path to vendor fingerprint YAML config")

	// Output options
	flag.StringVar(&config.OutputFormat, "output", "table", "Output format: json, csv, table, simple")
	flag.StringVar(&config.OutputFile, "output-file", "", "Output file")
	flag.BoolVar(&config.ShowDetails, "details", false, "Show detailed information")

	// Persistence options
	flag.StringVar(&config.DatabasePath, "database", "", "Database file")
	flag.BoolVar(&config.EnableDatabase, "enable-db", false, "Enable database persistence")

	// Discovery options
	pingTimeout := flag.Duration("ping-timeout", 500*time.Millisecond, "Ping timeout")
	portTimeout := flag.Duration("port-timeout", 1*time.Second, "Port timeout")
	flag.BoolVar(&config.DiscoveryScan, "discovery", false, "Network discovery")

	// Vendor debugging flags
	flag.BoolVar(&config.VendorDebug, "vendor-debug", false, "Enable vendor detection debugging")
	flag.StringVar(&config.VendorLogFile, "vendor-log", "", "Log vendor detection to file")

	// NEW: TCP pre-filtering options (Python-style optimization)
	tcpTimeout := flag.Duration("tcp-timeout", 2*time.Second, "TCP connectivity check timeout")
	flag.BoolVar(&config.SkipTCPCheck, "skip-tcp-check", false, "Skip TCP pre-filtering")
	tcpPortsStr := flag.String("tcp-ports", "20,21,22,25,53,80,161,443,515,631,993,995,9100",
		"TCP ports to check for connectivity (comma-separated)")

	// NEW: Enhanced SNMP options (Python-style fallback)
	flag.BoolVar(&config.EnableSNMPFallback, "enable-snmp-fallback", true, "Enable automatic SNMP version fallback")

	// Special flags
	version := flag.Bool("version", false, "Show version")
	help := flag.Bool("help", false, "Show help")

	flag.Parse()

	if *version {
		fmt.Printf("Go SNMP Toolkit CLI v%s\n", Version)
		os.Exit(0)
	}

	if *help {
		printUsage()
		os.Exit(0)
	}

	// Process parsed values
	config.Communities = strings.Split(*communities, ",")
	for i := range config.Communities {
		config.Communities[i] = strings.TrimSpace(config.Communities[i])
	}

	config.Timeout = *timeout
	config.PingTimeout = *pingTimeout
	config.PortTimeout = *portTimeout
	config.TCPCheckTimeout = *tcpTimeout

	// Parse TCP ports
	if *tcpPortsStr != "" {
		portStrs := strings.Split(*tcpPortsStr, ",")
		config.TCPCheckPorts = make([]int, 0, len(portStrs))
		for _, portStr := range portStrs {
			if port, err := strconv.Atoi(strings.TrimSpace(portStr)); err == nil {
				config.TCPCheckPorts = append(config.TCPCheckPorts, port)
			}
		}
	}

	// FAST MODE OPTIMIZATIONS (Python-style performance)
	if config.Fast {
		config.Timeout = 1 * time.Second
		config.PingTimeout = 300 * time.Millisecond
		config.PortTimeout = 500 * time.Millisecond
		config.TCPCheckTimeout = 1 * time.Second
		config.Retries = 1
		config.Concurrency = 100
		// Use fewer TCP ports in fast mode for better performance
		config.TCPCheckPorts = []int{22, 80, 161, 443}
	}

	// Handle vendor debugging (can use either flags or environment variables)
	if config.VendorDebug || os.Getenv("VENDOR_DEBUG") == "1" {
		config.VendorDebug = true
		os.Setenv("VENDOR_DEBUG", "1")
	}

	if config.VendorLogFile != "" || os.Getenv("VENDOR_LOG_FILE") != "" {
		if config.VendorLogFile == "" {
			config.VendorLogFile = os.Getenv("VENDOR_LOG_FILE")
		}
		os.Setenv("VENDOR_LOG_FILE", config.VendorLogFile)
	}

	// Load targets from file if specified
	if *targetsFile != "" {
		targets, err := loadTargetsFromFile(*targetsFile)
		if err != nil {
			log.Fatalf("Error loading targets file: %v", err)
		}
		config.Targets = targets
	}

	return config
}

func printUsage() {
	fmt.Printf(`Go SNMP Toolkit CLI v%s

USAGE:
    gosnmpcli -mode <mode> -target <target> [options]

MODES:
    scan        Perform network scan with SNMP detection
    fingerprint Perform vendor fingerprinting on targets
    test        Test SNMP connectivity to specific targets
    discover    Discover live hosts and services
    query       Query specific SNMP OIDs

EXAMPLES:
    # Basic network scan
    gosnmpcli -mode scan -target 192.168.1.0/24

    # Large network fast scan
    gosnmpcli -mode scan -target 10.0.0.0/16 -fast -concurrency 100

    # SNMPv3 scan with custom config
    gosnmpcli -mode scan -target 192.168.1.0/24 -snmp-version 3 \
              -username admin -auth-key authpass -priv-key privpass \
              -config ./my_vendor_config.yaml

    # Export results to CSV with persistence
    gosnmpcli -mode scan -target 192.168.1.0/24 -output csv -output-file results.csv \
              -enable-db -database ./devices.json

For more information, visit: https://github.com/scottpeterman/gosnmptk
`, Version)
}

func loadTargetsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			targets = append(targets, line)
		}
	}

	return targets, scanner.Err()
}

// Core Scanner Methods

func (s *CLIScanner) Cancel() {
	if s.cancel != nil {
		s.cancel()
	}
}

func (s *CLIScanner) runNetworkScan() {
	if s.config.Target == "" && len(s.config.Targets) == 0 {
		log.Fatal("Target required for scan mode")
	}

	// Expand all targets
	var allTargets []string
	if s.config.Target != "" {
		targets, err := s.generateIPs(s.config.Target)
		if err != nil {
			log.Fatalf("Error expanding target: %v", err)
		}
		allTargets = append(allTargets, targets...)
	}
	allTargets = append(allTargets, s.config.Targets...)

	if !s.config.Quiet {
		fmt.Printf("🔍 Starting network scan of %d targets...\n", len(allTargets))
		fmt.Printf("⚙️  Concurrency: %d, Timeout: %v, SNMP Communities: %v\n",
			s.config.Concurrency, s.config.Timeout, s.config.Communities)
		fmt.Println()
	}

	// Set up persistence if enabled
	if s.config.EnableDatabase && s.config.DatabasePath != "" {
		s.persistenceBridge = persistence.NewPersistenceBridge(s.config.DatabasePath, true)
		defer s.persistenceBridge.Close()
	}

	// Initialize scanning state
	atomic.StoreInt64(&s.total, int64(len(allTargets)))
	s.startTime = time.Now()

	// Scan all targets
	s.scanTargets(allTargets)
	s.outputResults()
}

func (s *CLIScanner) generateIPs(cidr string) ([]string, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}

	var ips []string
	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); s.inc(ip) {
		ips = append(ips, ip.String())
	}

	// Remove network and broadcast addresses for subnets smaller than /31
	ones, _ := ipNet.Mask.Size()
	if ones < 31 && len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}

	return ips, nil
}

func (s *CLIScanner) inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func (s *CLIScanner) scanTargets(targets []string) {
	if !s.config.Quiet {
		fmt.Printf("🔍 Starting optimized scan of %d targets...\n", len(targets))
		fmt.Printf("⚙️  Concurrency: %d, Timeout: %v\n", s.config.Concurrency, s.config.Timeout)
	}

	// Dynamic timeout based on network size
	ipCount := len(targets)
	var maxScanTime time.Duration
	switch {
	case ipCount > 32000: // /16 and larger
		maxScanTime = 4 * time.Hour
	case ipCount > 16000: // /17
		maxScanTime = 2 * time.Hour
	case ipCount > 8000: // /18-/19
		maxScanTime = 1 * time.Hour
	case ipCount > 4000: // /20
		maxScanTime = 30 * time.Minute
	case ipCount > 1000: // /21-/22
		maxScanTime = 20 * time.Minute
	case ipCount > 250: // /23-/24
		maxScanTime = 10 * time.Minute
	default: // Small networks
		maxScanTime = 5 * time.Minute
	}

	// Optimize for large networks
	if ipCount > 10000 {
		if s.config.Concurrency < 100 {
			s.config.Concurrency = 100
		}
		if s.config.Timeout > 2*time.Second {
			s.config.Timeout = 2 * time.Second
		}

		if !s.config.Quiet {
			fmt.Printf("⚡ Large network detected: Concurrency: %d, Timeout: %v\n",
				s.config.Concurrency, s.config.Timeout)
		}
	}

	if !s.config.Quiet {
		fmt.Printf("⏱️  Max scan time: %v\n\n", maxScanTime)
	}

	sem := make(chan struct{}, s.config.Concurrency)
	resultChan := make(chan CLIScanResult, s.config.Concurrency)

	// Progress tracking
	var scanned, found, snmpReady int64
	total := int64(len(targets))
	startTime := time.Now()

	// Progress reporting
	done := make(chan bool)
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				current := atomic.LoadInt64(&scanned)
				responding := atomic.LoadInt64(&found)
				snmpCount := atomic.LoadInt64(&snmpReady)
				elapsed := time.Since(startTime)

				if current > 0 && !s.config.Quiet {
					rate := float64(current) / elapsed.Seconds()
					var eta time.Duration
					if rate > 0 && total > current {
						remainingHosts := total - current
						eta = time.Duration(float64(remainingHosts)/rate) * time.Second
					}

					percentage := float64(current) / float64(total) * 100
					fmt.Printf("Progress: %d/%d (%.1f%%) | Found: %d responding, %d SNMP | Rate: %.1f/sec | ETA: %v\n",
						current, total, percentage, responding, snmpCount, rate, eta.Truncate(time.Second))
				}
			}
		}
	}()

	// Start workers
	var wg sync.WaitGroup
	for _, ip := range targets {
		select {
		case <-s.ctx.Done():
			break
		default:
		}

		wg.Add(1)
		go func(ipAddr string) {
			defer wg.Done()

			// Acquire semaphore
			select {
			case sem <- struct{}{}:
			case <-s.ctx.Done():
				return
			}
			defer func() {
				select {
				case <-sem:
				default:
				}
			}()

			// Check if cancelled
			select {
			case <-s.ctx.Done():
				return
			default:
			}

			// Scan host
			result := s.scanHost(ipAddr)
			atomic.AddInt64(&scanned, 1)
			atomic.AddInt64(&s.current, 1)

			select {
			case resultChan <- result:
			case <-s.ctx.Done():
				return
			}
		}(ip)
	}

	// Close result channel when all workers complete
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results with timeout protection
	collectTimeout := time.After(maxScanTime)

	for {
		select {
		case result, ok := <-resultChan:
			if !ok {
				// Channel closed, all done
				done <- true
				elapsed := time.Since(startTime)
				responding := atomic.LoadInt64(&found)
				snmpCount := atomic.LoadInt64(&snmpReady)

				if !s.config.Quiet {
					fmt.Printf("\n🎉 Scan complete! %d hosts scanned in %v\n", atomic.LoadInt64(&scanned), elapsed.Truncate(time.Second))
					fmt.Printf("📊 Results: %d responding, %d SNMP ready\n", responding, snmpCount)
				}
				return
			}

			// FILTER: Only store responding hosts
			if result.Responding {
				atomic.AddInt64(&found, 1)
				atomic.AddInt64(&s.found, 1)

				s.mu.Lock()
				s.results = append(s.results, result)
				s.mu.Unlock()

				if result.SNMPReady {
					atomic.AddInt64(&snmpReady, 1)
					atomic.AddInt64(&s.snmpReady, 1)
				}

				// Record to persistence if enabled
				if s.persistenceBridge != nil && result.Responding {
					s.recordScanResultToPersistence(result)
				}

				// Live feedback for CLI mode
				if !s.config.Quiet {
					if result.SNMPReady {
						vendor := result.DetectedVendor
						if vendor == "" {
							vendor = "unknown"
						}
						fmt.Printf("✅ %s - %s (%s)\n", result.IP, vendor, result.SNMPVersion)
					} else if s.config.Verbose {
						fmt.Printf("🔍 %s - responding (no SNMP)\n", result.IP)
					}
				}
			}

		case <-s.ctx.Done():
			// Cancelled
			done <- true
			return

		case <-collectTimeout:
			// Timeout protection
			done <- true
			fmt.Printf("⚠️  Scan timeout exceeded after %v\n", maxScanTime)
			return
		}
	}
}

func (s *CLIScanner) scanHost(ip string) CLIScanResult {
	result := CLIScanResult{
		IP:       ip,
		Hostname: ip,
		ScanTime: time.Now(),
	}

	// Check if scan was cancelled
	select {
	case <-s.ctx.Done():
		result.Error = "scan cancelled"
		return result
	default:
	}

	// Check basic connectivity first
	responding, rtt, err := s.testConnectivity(ip)
	result.Responding = responding
	result.RTT = rtt

	if err != nil {
		result.Error = err.Error()
	}

	if responding {
		// Get hostname via DNS (with timeout)
		result.Hostname = s.lookupHostname(ip)

		// Test SNMP with real client
		snmpReady, community, version, sysDescr, sysName, client := s.testSNMP(ip)
		result.SNMPReady = snmpReady
		result.SNMPCommunity = community
		result.SNMPVersion = version
		result.SystemDescr = sysDescr
		result.SystemName = sysName

		// Use SNMP sysName as hostname if available and more descriptive
		if sysName != "" && sysName != ip && len(sysName) > len(result.Hostname) {
			result.Hostname = sysName
		}

		// CRITICAL: Perform vendor detection using YAML configuration
		if result.SNMPReady && result.SystemDescr != "" {
			// Get sysObjectID if available
			var sysObjectID string
			if client != nil {
				sysObjectID, _ = client.Get("1.3.6.1.2.1.1.2.0")
			}

			// Log detection start with IP context
			s.vendorLogger.LogDetectionStart(ip, result.SystemDescr, sysObjectID)

			// PRIMARY: Use YAML-based detection first
			vendor, confidence, method := s.detectVendorFromYAML(result.SystemDescr, sysObjectID)

			// FALLBACK: Only use library detection if YAML detection fails
			if vendor == "unknown" || vendor == "" {
				vendor, confidence, method = fingerprint.DetectVendorComprehensive(
					result.SystemDescr,
					sysObjectID,
					result.SystemName,
					"", // enterprise OID
				)

				// Mark as fallback method
				if vendor != "unknown" && vendor != "" {
					method = "library_fallback"
				}
			}

			// Set the vendor detection results
			result.DetectedVendor = vendor
			result.VendorConfidence = confidence
			result.VendorMethod = method

			// Log the final result with IP context
			s.vendorLogger.LogDetectionResult(ip, vendor, confidence, method)

			// IMPORTANT: ALWAYS perform enhanced fingerprinting if we have a client
			// This allows vendor correction to happen first
			if client != nil && s.config.FingerprintType != "basic" {
				s.performYAMLBasedFingerprinting(client, &result)
			}

			// CRITICAL: ALWAYS set device type using YAML configuration
			// This should happen regardless of fingerprint type
			if s.config.Verbose {
				fmt.Printf("🔍 About to call detectDeviceTypeFromYAML with vendor='%s', sysDescr='%s'\n",
					result.DetectedVendor, s.truncateString(result.SystemDescr, 50))
			}

			result.DeviceType = s.detectDeviceTypeFromYAML(result.DetectedVendor, result.SystemDescr)

			if s.config.Verbose {
				fmt.Printf("🔍 Device type detection result: '%s'\n", result.DeviceType)
			}

			// Extract model using vendor-specific logic (using corrected vendor)
			result.Model = s.extractModelFromSysDescr(result.SystemDescr, result.DetectedVendor)

			// Debug output to verify vendor detection is working
			if s.config.Verbose {
				fmt.Printf("🔍 Final Vendor Detection: IP=%s, Vendor=%s, DeviceType=%s, Confidence=%s, Method=%s, SysOID=%s\n",
					ip, result.DetectedVendor, result.DeviceType, confidence, method, sysObjectID)
			}
		}

		// Close SNMP client after all operations
		if client != nil {
			client.Close()
		}
	}

	return result
}

func (s *CLIScanner) performYAMLBasedFingerprinting(client *snmp.Client, result *CLIScanResult) {
	if s.vendorConfig == nil {
		// Fallback to library-based fingerprinting
		s.performDetailedFingerprinting(client, result)
		return
	}

	result.FingerprintPerformed = true

	// Initialize vendor data
	if result.VendorData == nil {
		result.VendorData = make(map[string]string)
	}

	// Track which vendors respond to their specific OIDs
	vendorOIDMatches := make(map[string]int)
	detectedVendorFromOID := ""
	bestOIDScore := 0
	originalVendor := result.DetectedVendor

	// Test ALL vendors' OIDs, not just the initially detected vendor
	for vendorKey, vendorConfig := range s.vendorConfig.Vendors {
		if s.config.Verbose {
			fmt.Printf("🔍 Testing %s vendor-specific OIDs...\n", vendorKey)
		}

		vendorMatches := 0

		// Query vendor-specific OIDs from YAML configuration
		for _, yamlOID := range vendorConfig.FingerprintOIDs {
			// Check if this OID applies to the detected device type
			if len(yamlOID.DeviceTypes) > 0 {
				deviceTypeMatches := false
				for _, deviceType := range yamlOID.DeviceTypes {
					if deviceType == result.DeviceType {
						deviceTypeMatches = true
						break
					}
				}
				if !deviceTypeMatches {
					continue
				}
			}

			if s.config.Verbose {
				fmt.Printf("  Testing %s OID: %s (%s)\n", vendorKey, yamlOID.Name, yamlOID.OID)
			}

			// Query the OID
			value, err := client.Get(yamlOID.OID)
			if err != nil {
				if s.config.Verbose {
					fmt.Printf("    FAILED: %v\n", err)
				}
				continue
			}

			if value == "" || !s.isValidSNMPResponse(value) {
				if s.config.Verbose {
					fmt.Printf("    INVALID: %s\n", value)
				}
				continue
			}

			// SUCCESS! This vendor's OID responded
			vendorMatches++
			result.VendorData[yamlOID.Name] = value

			if s.config.Verbose {
				fmt.Printf("    SUCCESS: %s = %s\n", yamlOID.Name, s.truncateString(value, 40))
			}

			// Extract specific fields based on OID name/description
			s.extractFieldsFromYAMLFingerprint(yamlOID, value, result)

			// If this is a definitive OID, this vendor is confirmed
			if yamlOID.Definitive {
				if s.config.Verbose {
					fmt.Printf("    *** DEFINITIVE OID MATCH for %s ***\n", vendorKey)
				}
				detectedVendorFromOID = vendorKey
				bestOIDScore = 1000 // Definitive match gets highest score
				break
			}
		}

		// Track vendor matches
		if vendorMatches > 0 {
			vendorOIDMatches[vendorKey] = vendorMatches
			if s.config.Verbose {
				fmt.Printf("  %s: %d OIDs responded\n", vendorKey, vendorMatches)
			}

			// Update best OID-based detection (non-definitive)
			if detectedVendorFromOID == "" && vendorMatches > bestOIDScore {
				detectedVendorFromOID = vendorKey
				bestOIDScore = vendorMatches
			}
		}

		// Break if we found a definitive match
		if bestOIDScore >= 1000 {
			break
		}
	}

	// Query generic OIDs if available
	for _, genericOID := range s.vendorConfig.GenericOIDs {
		value, err := client.Get(genericOID.OID)
		if err != nil {
			continue
		}

		if value != "" && s.isValidSNMPResponse(value) {
			result.VendorData[genericOID.Name] = value
			s.extractFieldsFromYAMLFingerprintGeneric(genericOID, value, result)
		}
	}

	// UPDATE VENDOR BASED ON SUCCESSFUL OID RESPONSES
	if detectedVendorFromOID != "" && detectedVendorFromOID != "unknown" {
		if originalVendor == "unknown" || originalVendor == "" || bestOIDScore >= 1000 {
			if s.config.Verbose {
				fmt.Printf("🎯 VENDOR CORRECTION: %s -> %s (based on %d successful OIDs)\n",
					originalVendor, detectedVendorFromOID, bestOIDScore)
			}

			result.DetectedVendor = detectedVendorFromOID

			// Update confidence and method
			if bestOIDScore >= 1000 {
				result.VendorConfidence = "high"
				result.VendorMethod = "definitive_oid_match"
			} else {
				result.VendorConfidence = "high"
				result.VendorMethod = fmt.Sprintf("oid_based_detection_%d_matches", bestOIDScore)
			}

			// Also update device type based on the corrected vendor
			if correctedDeviceType := s.detectDeviceTypeFromYAML(detectedVendorFromOID, result.SystemDescr); correctedDeviceType != "" {
				if s.config.Verbose {
					fmt.Printf("🎯 DEVICE TYPE CORRECTION: %s -> %s\n", result.DeviceType, correctedDeviceType)
				}
				result.DeviceType = correctedDeviceType
			}
		} else {
			fmt.Printf("No DEVICE TYPE CORRECTION needed: %s already detected as %s\n", originalVendor, detectedVendorFromOID)
		}
	}

	// Log the final result
	if s.config.Verbose {
		fmt.Printf("🔍 Final result: Vendor=%s, Confidence=%s, Method=%s\n",
			result.DetectedVendor, result.VendorConfidence, result.VendorMethod)

		if len(vendorOIDMatches) > 0 {
			fmt.Printf("🔍 Vendor OID matches: %v\n", vendorOIDMatches)
		}
	}

	// If we still don't have model/serial/firmware, try library fingerprinting as enhancement
	if result.Model == "" || result.SerialNumber == "" || result.FirmwareVersion == "" {
		s.performDetailedFingerprinting(client, result)
	}
}
func (s *CLIScanner) isValidSNMPResponse(value string) bool {
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

func (s *CLIScanner) extractFieldsFromYAMLFingerprintGeneric(oid FingerprintOID, value string, result *CLIScanResult) {
	nameLower := strings.ToLower(oid.Name)
	descLower := strings.ToLower(oid.Description)

	// Model detection
	if (strings.Contains(nameLower, "model") ||
		strings.Contains(nameLower, "platform") ||
		strings.Contains(descLower, "model")) && result.Model == "" {
		result.Model = value
	}

	// Serial number detection
	if (strings.Contains(nameLower, "serial") ||
		strings.Contains(nameLower, "service tag") ||
		strings.Contains(descLower, "serial")) && result.SerialNumber == "" {
		result.SerialNumber = value
	}

	// Firmware/software version detection
	if (strings.Contains(nameLower, "version") ||
		strings.Contains(nameLower, "firmware") ||
		strings.Contains(nameLower, "software") ||
		strings.Contains(descLower, "version")) && result.FirmwareVersion == "" {
		result.FirmwareVersion = value
	}
}

func (s *CLIScanner) extractFieldsFromYAMLFingerprint(oid FingerprintOID, value string, result *CLIScanResult) {
	nameLower := strings.ToLower(oid.Name)
	descLower := strings.ToLower(oid.Description)

	// Model detection
	if (strings.Contains(nameLower, "model") ||
		strings.Contains(nameLower, "platform") ||
		strings.Contains(descLower, "model")) && result.Model == "" {
		result.Model = value
	}

	// Serial number detection
	if (strings.Contains(nameLower, "serial") ||
		strings.Contains(nameLower, "service tag") ||
		strings.Contains(descLower, "serial")) && result.SerialNumber == "" {
		result.SerialNumber = value
	}

	// Firmware/software version detection
	if (strings.Contains(nameLower, "version") ||
		strings.Contains(nameLower, "firmware") ||
		strings.Contains(nameLower, "software") ||
		strings.Contains(descLower, "version")) && result.FirmwareVersion == "" {
		result.FirmwareVersion = value
	}
}

// Fallback library-based fingerprinting (keep existing method)
func (s *CLIScanner) performDetailedFingerprinting(client *snmp.Client, result *CLIScanResult) {
	fpClient := fingerprint.NewClient(client)
	fpClient.SetTimeout(5 * time.Second)

	ctx := context.Background()
	fpResult, err := fpClient.PerformFingerprinting(ctx, result.DetectedVendor)

	if err != nil {
		result.FingerprintError = err.Error()
		return
	}

	if fpResult != nil {
		// Only enhance vendor info if the detailed fingerprinting provides better data
		if fpResult.DetectedVendor != "unknown" && fpResult.DetectedVendor != "" {
			// Only override if confidence is higher
			if fpResult.Confidence == "high" && result.VendorConfidence != "high" {
				result.DetectedVendor = fpResult.DetectedVendor
				result.VendorConfidence = fpResult.Confidence
				result.VendorMethod = fpResult.DetectionMethod + "_library_enhanced"
			}
		}

		// Initialize vendor data if needed
		if result.VendorData == nil {
			result.VendorData = make(map[string]string)
		}

		// Merge vendor data
		for k, v := range fpResult.FingerprintData {
			result.VendorData[k] = v
		}

		// Extract additional fields from detailed fingerprinting
		if fpResult.FingerprintData != nil {
			if model := s.extractFieldFromData(fpResult.FingerprintData, "model", "product", "chassis"); model != "" && result.Model == "" {
				result.Model = model
			}
			if serial := s.extractFieldFromData(fpResult.FingerprintData, "serial", "service tag"); serial != "" && result.SerialNumber == "" {
				result.SerialNumber = serial
			}
			if firmware := s.extractFieldFromData(fpResult.FingerprintData, "version", "firmware", "software"); firmware != "" && result.FirmwareVersion == "" {
				result.FirmwareVersion = firmware
			}
		}
	}
}

// Enhanced built-in vendor detection as final fallback (only when YAML fails)
func (s *CLIScanner) detectVendorBuiltIn(sysDescrLower string) (string, string, string) {
	if s.config.Verbose {
		fmt.Printf("🔍 Using built-in fallback patterns for: %s\n", s.truncateString(sysDescrLower, 60))
	}

	// Only the most essential patterns as fallback
	essentialPatterns := map[string][]string{
		"cisco":   {"cisco", "ios", "catalyst", "nexus", "cupertino", "cat9k"},
		"arista":  {"arista", "eos"},
		"hp":      {"hp ", "hpe ", "jetdirect"},
		"lexmark": {"lexmark"},
		"dell":    {"dell", "idrac"},
	}

	for vendor, patterns := range essentialPatterns {
		for _, pattern := range patterns {
			if strings.Contains(sysDescrLower, pattern) {
				if s.config.Verbose {
					fmt.Printf("🔍 Built-in fallback matched %s with pattern: %s\n", vendor, pattern)
				}
				return vendor, "medium", "builtin_fallback"
			}
		}
	}

	return "unknown", "none", "no_pattern_match"
}

// Helper function to truncate strings for debugging
func (s *CLIScanner) truncateString(str string, maxLen int) string {
	if len(str) <= maxLen {
		return str
	}
	return str[:maxLen] + "..."
}

func (s *CLIScanner) testConnectivity(ip string) (bool, time.Duration, error) {
	start := time.Now()

	// TCP ports only (no ping) - exact GUI logic
	ports := []string{"80", "443", "22", "23", "161", "8080"}
	timeoutPerPort := s.config.Timeout / time.Duration(len(ports))

	// Minimum timeout to prevent too-short timeouts
	if timeoutPerPort < 100*time.Millisecond {
		timeoutPerPort = 100 * time.Millisecond
	}

	for _, port := range ports {
		// Check for cancellation
		select {
		case <-s.ctx.Done():
			return false, time.Since(start), fmt.Errorf("cancelled")
		default:
		}

		conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, port), timeoutPerPort)
		if err == nil {
			conn.Close()
			return true, time.Since(start), nil
		}
	}

	return false, time.Since(start), fmt.Errorf("no services responding")
}

func (s *CLIScanner) lookupHostname(ip string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ip
	}
	return strings.TrimSuffix(names[0], ".")
}

// YAML-based vendor detection with built-in fallback

func (s *CLIScanner) detectVendorFromYAML(sysDescr, sysObjectID string) (string, string, string) {
	// Log detection start (without IP for this function - IP is logged in scanHost)
	s.vendorLogger.LogDetectionStart("", sysDescr, sysObjectID)

	if sysDescr == "" && sysObjectID == "" {
		s.vendorLogger.LogDetectionResult("", "unknown", "none", "no_data")
		return "unknown", "none", "no_data"
	}

	sysDescrLower := strings.ToLower(sysDescr)
	sysObjectIDLower := strings.ToLower(sysObjectID)

	// If YAML config is loaded, use it with priority order
	if s.vendorConfig != nil {
		// Use priority order from YAML config
		for priority, vendorName := range s.vendorConfig.DetectionRules.PriorityOrder {
			vendorConfig, exists := s.vendorConfig.Vendors[vendorName]
			if !exists {
				continue
			}

			// Log vendor test start
			s.vendorLogger.LogVendorTest(vendorName, priority,
				vendorConfig.DetectionPatterns, vendorConfig.ExclusionPatterns)

			// Check exclusion patterns first (critical for ION vs Cisco confusion)
			excluded := false
			excludedBy := ""
			for _, exclusionPattern := range vendorConfig.ExclusionPatterns {
				exclusionLower := strings.ToLower(exclusionPattern)
				if strings.Contains(sysDescrLower, exclusionLower) ||
					strings.Contains(sysObjectIDLower, exclusionLower) {
					excluded = true
					excludedBy = exclusionPattern
					s.vendorLogger.LogPatternMatch(vendorName, exclusionPattern, sysDescr, true, true)
					break
				}
			}

			if excluded {
				if s.config.Verbose {
					fmt.Printf("🔍 Excluded %s due to pattern: %s\n", vendorName, excludedBy)
				}
				continue
			}

			// Check sysObjectID enterprise OID first (highest confidence)
			if sysObjectID != "" && vendorConfig.EnterpriseOID != "" {
				if strings.HasPrefix(sysObjectID, vendorConfig.EnterpriseOID) {
					if s.config.Verbose {
						fmt.Printf("🔍 Matched %s by enterprise OID: %s\n", vendorName, vendorConfig.EnterpriseOID)
					}
					s.vendorLogger.LogDetectionResult("", vendorName, "high", "yaml_enterprise_oid")
					return vendorName, "high", "yaml_enterprise_oid"
				}
			}

			// Check OID patterns in sysObjectID
			for _, pattern := range vendorConfig.OIDPatterns {
				patternLower := strings.ToLower(pattern)
				matched := (sysObjectID != "" && strings.Contains(sysObjectIDLower, patternLower)) ||
					strings.Contains(sysDescrLower, patternLower)

				if matched {
					if s.config.Verbose {
						fmt.Printf("🔍 Matched %s by OID pattern: %s\n", vendorName, pattern)
					}
					s.vendorLogger.LogPatternMatch(vendorName, pattern, sysDescr, true, false)
					s.vendorLogger.LogDetectionResult("", vendorName, "medium", "yaml_oid_pattern")
					return vendorName, "medium", "yaml_oid_pattern"
				}
			}

			// Check detection patterns in sysDescr
			for _, pattern := range vendorConfig.DetectionPatterns {
				patternLower := strings.ToLower(pattern)
				matched := strings.Contains(sysDescrLower, patternLower)

				// Always log pattern tests for debugging
				s.vendorLogger.LogPatternMatch(vendorName, pattern, sysDescr, matched, false)

				if matched {
					if s.config.Verbose {
						fmt.Printf("🔍 Matched %s by detection pattern: %s\n", vendorName, pattern)
					}
					s.vendorLogger.LogDetectionResult("", vendorName, "high", "yaml_detection_pattern")
					return vendorName, "high", "yaml_detection_pattern"
				}
			}
		}

		if s.config.Verbose {
			fmt.Printf("🔍 No YAML vendor match found for sysDescr: %s\n", s.truncateString(sysDescr, 60))
		}
	} else {
		if s.config.Verbose {
			fmt.Printf("⚠️  No YAML config loaded, using built-in patterns\n")
		}
		s.vendorLogger.LogYAMLConfigStatus(false, 0, nil)
	}

	// Fallback to built-in patterns only if YAML config not available
	vendor, confidence, method := s.detectVendorBuiltIn(sysDescrLower)
	s.vendorLogger.LogDetectionResult("", vendor, confidence, method)
	return vendor, confidence, method
}

func getMapKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func (s *CLIScanner) detectDeviceTypeFromYAML(vendor, sysDescr string) string {
	// Add debug output at the beginning
	if s.config.Verbose {
		fmt.Printf("🔍 DEBUG detectDeviceTypeFromYAML called: vendor='%s', sysDescr='%s'\n",
			vendor, s.truncateString(sysDescr, 50))
	}

	if s.vendorConfig == nil || vendor == "" || vendor == "unknown" {
		if s.config.Verbose {
			fmt.Printf("🔍 DEBUG: Using generic detection (vendorConfig=%t, vendor='%s')\n",
				s.vendorConfig != nil, vendor)
		}
		return s.detectDeviceTypeGeneric(sysDescr)
	}

	vendorConfig, exists := s.vendorConfig.Vendors[vendor]
	if !exists {
		if s.config.Verbose {
			fmt.Printf("🔍 DEBUG: Vendor '%s' not found in config, using generic\n", vendor)
		}
		return s.detectDeviceTypeGeneric(sysDescr)
	}

	if s.config.Verbose {
		fmt.Printf("🔍 DEBUG: Found vendor config for '%s' with %d device types\n",
			vendor, len(vendorConfig.DeviceTypes))
	}

	sysDescrLower := strings.ToLower(sysDescr)

	// DEBUG: Add logging to see what's happening
	if s.config.Verbose {
		fmt.Printf("🔍 DEBUG detectDeviceTypeFromYAML:\n")
		fmt.Printf("  Vendor: %s\n", vendor)
		fmt.Printf("  sysDescr: %s\n", sysDescr)
		fmt.Printf("  sysDescrLower: %s\n", sysDescrLower)
		fmt.Printf("  Has overrides: %t\n", len(vendorConfig.DeviceTypeOverrides) > 0)
		if len(vendorConfig.DeviceTypeOverrides) > 0 {
			fmt.Printf("  Override keys: %v\n", getMapKeys(vendorConfig.DeviceTypeOverrides))
		}
	}

	// NEW: Check device type overrides FIRST
	if len(vendorConfig.DeviceTypeOverrides) > 0 {
		for deviceType, patterns := range vendorConfig.DeviceTypeOverrides {
			if s.config.Verbose {
				fmt.Printf("  Testing device type: %s with %d patterns\n", deviceType, len(patterns))
			}

			for _, pattern := range patterns {
				patternLower := strings.ToLower(pattern)
				if s.config.Verbose {
					fmt.Printf("    Testing pattern: '%s'\n", pattern)
					fmt.Printf("    Pattern lower: '%s'\n", patternLower)
					fmt.Printf("    Contains check: %t\n", strings.Contains(sysDescrLower, patternLower))
				}

				if strings.Contains(sysDescrLower, patternLower) {
					// Verify this device type is allowed for this vendor
					for _, allowedType := range vendorConfig.DeviceTypes {
						if allowedType == deviceType {
							if s.config.Verbose {
								fmt.Printf("🎯 Device type override SUCCESS: %s -> %s (pattern: %s)\n",
									vendor, deviceType, pattern)
							}
							return deviceType
						}
					}
					if s.config.Verbose {
						fmt.Printf("    Pattern matched but device type '%s' not in allowed types: %v\n",
							deviceType, vendorConfig.DeviceTypes)
					}
				}
			}
		}
		if s.config.Verbose {
			fmt.Printf("  No override patterns matched, falling back to generic detection\n")
		}
	}

	// If vendor has only one device type, use it
	if len(vendorConfig.DeviceTypes) == 1 {
		if s.config.Verbose {
			fmt.Printf("🔍 Using single device type for %s: %s\n", vendor, vendorConfig.DeviceTypes[0])
		}
		return vendorConfig.DeviceTypes[0]
	}

	// Continue with existing pattern matching...
	typePatterns := map[string][]string{
		"switch":                {"switch", "switching", "catalyst", "nexus", "dcs-", "procurve"},
		"router":                {"router", "routing", "isr", "asr", "mx", "srx"},
		"firewall":              {"firewall", "security gateway", "pix", "asa", "fortigate", "pan-os"},
		"wireless":              {"wireless", "access point", "ap", "wifi", "fortiap"},
		"wireless_controller":   {"wireless controller", "wlc", "aruba networks wireless"},
		"printer":               {"printer", "laserjet", "officejet", "deskjet", "lexmark", "envy", "photosmart"},
		"multifunction_printer": {"multifunction", "mfp", "mx822ade", "cx943adxse"},
		"ups":                   {"ups", "uninterruptible", "apc"},
		"pdu":                   {"pdu", "power distribution"},
		"server":                {"server", "poweredge", "idrac"},
		"storage":               {"storage", "powervault", "san"},
		"sdwan_gateway":         {"ion ", "cloudgenix", "prisma sd-wan", "sd-wan"},
		"edge_device":           {"edge", "branch"},
		"management":            {"panorama", "management"},
		"print_server":          {"jetdirect", "print server"},
		"network_interface":     {"network interface", "jetdirect"},
		"access_point":          {"access point", "ap"},
	}

	// Check patterns in order of specificity
	for deviceType, patterns := range typePatterns {
		// Check if this device type is allowed for this vendor
		allowed := false
		for _, allowedType := range vendorConfig.DeviceTypes {
			if allowedType == deviceType {
				allowed = true
				break
			}
		}
		if !allowed {
			continue
		}

		// Check if any pattern matches
		for _, pattern := range patterns {
			if strings.Contains(sysDescrLower, pattern) {
				if s.config.Verbose {
					fmt.Printf("🔍 Detected device type %s for %s using pattern: %s\n", deviceType, vendor, pattern)
				}
				return deviceType
			}
		}
	}

	// Fallback to first allowed device type
	if len(vendorConfig.DeviceTypes) > 0 {
		if s.config.Verbose {
			fmt.Printf("🔍 Using fallback device type for %s: %s\n", vendor, vendorConfig.DeviceTypes[0])
		}
		return vendorConfig.DeviceTypes[0]
	}

	return s.detectDeviceTypeGeneric(sysDescr)
}

func (s *CLIScanner) detectDeviceTypeGeneric(sysDescr string) string {
	if sysDescr == "" {
		return ""
	}

	sysDescrLower := strings.ToLower(sysDescr)

	// Generic patterns
	if strings.Contains(sysDescrLower, "switch") {
		return "switch"
	}
	if strings.Contains(sysDescrLower, "router") {
		return "router"
	}
	if strings.Contains(sysDescrLower, "firewall") {
		return "firewall"
	}
	if strings.Contains(sysDescrLower, "printer") {
		return "printer"
	}
	if strings.Contains(sysDescrLower, "ups") {
		return "ups"
	}

	return ""
}

func (s *CLIScanner) extractModelFromSysDescr(sysDescr, vendor string) string {
	if sysDescr == "" {
		return ""
	}

	switch vendor {
	case "cisco":
		return s.extractCiscoModel(sysDescr)
	case "arista":
		return s.extractAristaModel(sysDescr)
	case "juniper":
		return s.extractJuniperModel(sysDescr)
	}

	return ""
}

func (s *CLIScanner) extractCiscoModel(sysDescr string) string {
	patterns := []string{
		`CAT9K[A-Z0-9_-]+`,
		`Catalyst [A-Z0-9-]+`,
		`ASA[0-9-]+`,
		`ISR[0-9-]+`,
		`ASR[0-9-]+`,
		`CSR[0-9-]+`,
		`Nexus [0-9-]+`,
	}

	for _, pattern := range patterns {
		if matches := regexp.MustCompile(pattern).FindStringSubmatch(sysDescr); len(matches) > 0 {
			return matches[0]
		}
	}
	return ""
}

func (s *CLIScanner) extractAristaModel(sysDescr string) string {
	pattern := `DCS-[A-Z0-9-]+`
	if matches := regexp.MustCompile(pattern).FindStringSubmatch(sysDescr); len(matches) > 0 {
		return matches[0]
	}
	return ""
}

func (s *CLIScanner) extractJuniperModel(sysDescr string) string {
	patterns := []string{
		`EX[0-9-]+`,
		`MX[0-9-]+`,
		`QFX[0-9-]+`,
		`SRX[0-9-]+`,
	}

	for _, pattern := range patterns {
		if matches := regexp.MustCompile(pattern).FindStringSubmatch(sysDescr); len(matches) > 0 {
			return matches[0]
		}
	}
	return ""
}

func (s *CLIScanner) extractFieldFromData(data map[string]string, keywords ...string) string {
	for key, value := range data {
		keyLower := strings.ToLower(key)
		for _, keyword := range keywords {
			if strings.Contains(keyLower, keyword) {
				return value
			}
		}
	}
	return ""
}

// Persistence methods - FIXED to preserve vendor detection
func (s *CLIScanner) recordScanResultToPersistence(result CLIScanResult) {
	if s.persistenceBridge == nil {
		return
	}

	// Debug: Show what we're trying to persist
	if s.config.Verbose {
		fmt.Printf("🔍 Persisting: IP=%s, Vendor=%s, DeviceType=%s, Model=%s\n",
			result.IP, result.DetectedVendor, result.DeviceType, result.Model)
	}

	legacyResult := persistence.LegacyFingerprint{
		IPAddress:       result.IP,
		Vendor:          result.DetectedVendor, // This should NOT be empty
		DeviceType:      result.DeviceType,
		Model:           result.Model,
		SerialNumber:    result.SerialNumber,
		OSVersion:       result.FirmwareVersion,
		SysObjectID:     s.extractSysObjectID(result),
		SysDescr:        result.SystemDescr,
		SNMPData:        s.convertVendorDataToSNMPData(result),
		ConfidenceScore: s.convertConfidenceToScore(result.VendorConfidence),
		DetectionMethod: result.VendorMethod,
	}

	// Debug: Show what we're actually sending to persistence
	if s.config.Verbose {
		fmt.Printf("🔍 LegacyFingerprint: Vendor=%s, DeviceType=%s, Model=%s, Method=%s\n",
			legacyResult.Vendor, legacyResult.DeviceType, legacyResult.Model, legacyResult.DetectionMethod)
	}

	s.persistenceBridge.RecordScanResult(legacyResult)
}

func (s *CLIScanner) convertVendorDataToSNMPData(result CLIScanResult) map[string]string {
	snmpData := make(map[string]string)

	if result.SystemDescr != "" {
		snmpData["1.3.6.1.2.1.1.1.0"] = result.SystemDescr
	}
	if result.SystemName != "" {
		snmpData["1.3.6.1.2.1.1.5.0"] = result.SystemName
	}

	if result.VendorData != nil {
		for key, value := range result.VendorData {
			snmpData[key] = value
		}
	}

	return snmpData
}

func (s *CLIScanner) convertConfidenceToScore(confidence string) int {
	switch strings.ToLower(confidence) {
	case "high":
		return 90
	case "medium":
		return 70
	case "low":
		return 50
	default:
		return 30
	}
}

// CLI mode functions

func (s *CLIScanner) runFingerprinting() {
	log.Println("Fingerprinting mode - use scan mode with fingerprinting enabled")
}

func (s *CLIScanner) runSNMPTest() {
	if s.config.Target == "" {
		log.Fatal("Target required for test mode")
	}

	if !s.config.Quiet {
		fmt.Printf("🧪 Testing SNMP connectivity to %s...\n", s.config.Target)
	}

	result := s.scanHost(s.config.Target)

	s.mu.Lock()
	s.results = append(s.results, result)
	s.mu.Unlock()

	s.outputResults()
}

func (s *CLIScanner) runDiscovery() {
	s.config.FingerprintType = ""
	s.runNetworkScan()
}

func (s *CLIScanner) runOIDQuery() {
	fmt.Printf("🔍 OID query functionality - to be implemented\n")
}

// Output methods

func (s *CLIScanner) outputResults() {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.results) == 0 {
		if !s.config.Quiet {
			fmt.Println("No results to display")
		}
		return
	}

	switch s.config.OutputFormat {
	case "json":
		s.outputJSON()
	case "csv":
		s.outputCSV()
	case "simple":
		s.outputSimple()
	default:
		s.outputTable()
	}
}

func (s *CLIScanner) outputJSON() {
	var output interface{}
	if s.config.ShowDetails {
		output = s.results
	} else {
		simplified := make([]map[string]interface{}, len(s.results))
		for i, result := range s.results {
			simplified[i] = map[string]interface{}{
				"ip":              result.IP,
				"hostname":        result.Hostname,
				"responding":      result.Responding,
				"snmp_ready":      result.SNMPReady,
				"detected_vendor": result.DetectedVendor,
				"device_type":     result.DeviceType,
				"model":           result.Model,
			}
		}
		output = simplified
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		log.Fatalf("Error encoding JSON: %v", err)
	}

	if s.config.OutputFile != "" {
		err = os.WriteFile(s.config.OutputFile, data, 0644)
		if err != nil {
			log.Fatalf("Error writing output file: %v", err)
		}
		if !s.config.Quiet {
			fmt.Printf("Results written to %s\n", s.config.OutputFile)
		}
	} else {
		fmt.Println(string(data))
	}
}

func (s *CLIScanner) outputCSV() {
	var output [][]string

	// Standard CSV output with essential fields including system description for gap analysis
	output = append(output, []string{
		"IP", "Hostname", "Responding", "SNMP_Ready", "SNMP_Version",
		"Detected_Vendor", "Vendor_Confidence", "Device_Type", "Model",
		"Serial", "Firmware", "System_Description", "Error",
	})

	for _, result := range s.results {
		rttMs := ""
		if result.RTT > 0 {
			rttMs = fmt.Sprintf("%.1f", float64(result.RTT.Nanoseconds())/1000000)
		}
		fmt.Print(rttMs)
		row := []string{
			result.IP,
			result.Hostname,
			fmt.Sprintf("%t", result.Responding),
			fmt.Sprintf("%t", result.SNMPReady),
			result.SNMPVersion,
			result.DetectedVendor,
			result.VendorConfidence,
			result.DeviceType,
			result.Model,
			result.SerialNumber,
			result.FirmwareVersion,
			result.SystemDescr, // System description always included
			result.Error,
		}
		output = append(output, row)
	}

	if s.config.OutputFile != "" {
		file, err := os.Create(s.config.OutputFile)
		if err != nil {
			log.Fatalf("Error creating output file: %v", err)
		}
		defer file.Close()

		writer := csv.NewWriter(file)
		defer writer.Flush()

		for _, row := range output {
			if err := writer.Write(row); err != nil {
				log.Fatalf("Error writing CSV: %v", err)
			}
		}

		if !s.config.Quiet {
			fmt.Printf("Results written to %s\n", s.config.OutputFile)
		}
	} else {
		writer := csv.NewWriter(os.Stdout)
		defer writer.Flush()

		for _, row := range output {
			writer.Write(row)
		}
	}
}

func (s *CLIScanner) outputSimple() {
	for _, result := range s.results {
		if result.Responding {
			if result.SNMPReady {
				vendor := result.DetectedVendor
				if vendor == "" {
					vendor = "unknown"
				}
				fmt.Printf("%s - %s (%s)\n", result.IP, vendor, result.SNMPVersion)
			} else {
				fmt.Printf("%s - responding (no SNMP)\n", result.IP)
			}
		}
	}
}

func (s *CLIScanner) outputTable() {
	// Calculate column widths
	ipWidth := 15
	hostnameWidth := 20
	statusWidth := 12
	snmpWidth := 10
	vendorWidth := 15
	modelWidth := 20

	// Adjust widths based on content
	for _, result := range s.results {
		if len(result.IP) > ipWidth {
			ipWidth = len(result.IP)
		}
		if len(result.Hostname) > hostnameWidth {
			hostnameWidth = len(result.Hostname)
		}
		if len(result.DetectedVendor) > vendorWidth {
			vendorWidth = len(result.DetectedVendor)
		}
		if len(result.Model) > modelWidth {
			modelWidth = len(result.Model)
		}
	}

	// Limit maximum widths
	if hostnameWidth > 30 {
		hostnameWidth = 30
	}
	if vendorWidth > 20 {
		vendorWidth = 20
	}
	if modelWidth > 25 {
		modelWidth = 25
	}

	// Print header
	format := fmt.Sprintf("%%-%ds | %%-%ds | %%-%ds | %%-%ds | %%-%ds | %%-%ds\n",
		ipWidth, hostnameWidth, statusWidth, snmpWidth, vendorWidth, modelWidth)

	fmt.Printf(format, "IP Address", "Hostname", "Status", "SNMP", "Vendor", "Model")
	fmt.Println(strings.Repeat("-", ipWidth+hostnameWidth+statusWidth+snmpWidth+vendorWidth+modelWidth+15))

	// Print results
	for _, result := range s.results {
		hostname := result.Hostname
		if len(hostname) > hostnameWidth {
			hostname = hostname[:hostnameWidth-3] + "..."
		}

		status := "Down"
		if result.Responding {
			status = "Up"
		}

		snmpStatus := "No"
		if result.SNMPReady {
			snmpStatus = "Yes"
		}

		vendor := result.DetectedVendor
		if vendor == "" {
			vendor = "-"
		}
		if len(vendor) > vendorWidth {
			vendor = vendor[:vendorWidth-3] + "..."
		}

		model := result.Model
		if model == "" {
			model = "-"
		}
		if len(model) > modelWidth {
			model = model[:modelWidth-3] + "..."
		}

		fmt.Printf(format, result.IP, hostname, status, snmpStatus, vendor, model)
	}

	// Print summary
	responding := 0
	snmpReady := 0
	fingerprinted := 0

	for _, result := range s.results {
		if result.Responding {
			responding++
		}
		if result.SNMPReady {
			snmpReady++
		}
		if result.DetectedVendor != "" && result.DetectedVendor != "unknown" {
			fingerprinted++
		}
	}

	fmt.Println()
	fmt.Printf("Summary: %d total, %d responding, %d SNMP ready, %d fingerprinted\n",
		len(s.results), responding, snmpReady, fingerprinted)
}

// checkSinglePort checks if a single port is open
func (tc *TCPPortChecker) checkSinglePort(ctx context.Context, ipAddress string, port int) bool {
	// Calculate remaining timeout
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(tc.timeout)
	}

	timeout := time.Until(deadline)
	if timeout <= 0 {
		return false
	}

	// Attempt TCP connection
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ipAddress, port), timeout)
	if err != nil {
		return false
	}

	// Close connection immediately
	conn.Close()
	return true
}

// SmartFieldExtractor handles intelligent field extraction from SNMP data
type SmartFieldExtractor struct {
	vendorConfig *VendorFingerprintConfig
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

// Add this method to your CLIScanner in main.go

// testSNMP tests SNMP connectivity with fallback support
func (s *CLIScanner) testSNMP(ip string) (bool, string, string, string, string, *snmp.Client) {
	// Use the enhanced fallback method from snmp_fallback.go
	result := s.testSNMPWithFallback(ip)

	if result.Success {
		return true, result.Community, result.Version, result.SysDescr, result.SysName, result.Client
	}

	return false, "", "", "", "", nil
}

// Alternative implementation if you want to keep it self-contained in main.go:
func (s *CLIScanner) testSNMPStandalone(ip string) (bool, string, string, string, string, *snmp.Client) {
	port := uint16(161)

	// If SNMPv3 is explicitly requested, try only SNMPv3
	if s.config.Version == 3 {
		if s.config.Username == "" {
			return false, "", "", "", "", nil
		}

		client := snmp.NewSNMPv3Client(
			ip, port,
			s.config.Username,
			s.config.AuthKey,
			s.config.PrivKey,
		)

		client.AuthProtocol = snmp.AuthProtocolFromString(s.config.AuthProtocol)
		client.PrivProtocol = snmp.PrivProtocolFromString(s.config.PrivProtocol)
		client.Timeout = s.config.Timeout
		client.Retries = s.config.Retries

		if err := client.Connect(); err == nil {
			if sysDescr, err := client.TestConnection(); err == nil {
				sysName, _ := client.Get("1.3.6.1.2.1.1.5.0")
				return true, s.config.Username, "SNMPv3", sysDescr, sysName, client
			}
		}
		client.Close()
		return false, "", "", "", "", nil
	}

	// Try SNMPv2c/v1 communities
	for _, community := range s.config.Communities {
		client := snmp.NewClient(ip, port)
		client.Community = community

		// Set the correct SNMP version
		if s.config.Version == 1 {
			client.Version = 0 // SNMPv1
		} else {
			client.Version = 1 // SNMPv2c (default)
		}

		client.Timeout = s.config.Timeout
		client.Retries = s.config.Retries

		if err := client.Connect(); err != nil {
			client.Close()
			continue
		}

		sysDescr, err := client.TestConnection()
		if err != nil {
			client.Close()
			continue
		}

		sysName, _ := client.Get("1.3.6.1.2.1.1.5.0")
		versionStr := "SNMPv2c"
		if s.config.Version == 1 {
			versionStr = "SNMPv1"
		}
		return true, community, versionStr, sysDescr, sysName, client
	}

	// Try SNMPv3 as fallback if username is provided and no explicit version
	if s.config.Version == 0 && s.config.Username != "" {
		client := snmp.NewSNMPv3Client(
			ip, port,
			s.config.Username,
			s.config.AuthKey,
			s.config.PrivKey,
		)

		client.AuthProtocol = snmp.AuthProtocolFromString(s.config.AuthProtocol)
		client.PrivProtocol = snmp.PrivProtocolFromString(s.config.PrivProtocol)
		client.Timeout = s.config.Timeout
		client.Retries = s.config.Retries

		if err := client.Connect(); err == nil {
			if sysDescr, err := client.TestConnection(); err == nil {
				sysName, _ := client.Get("1.3.6.1.2.1.1.5.0")
				return true, s.config.Username, "SNMPv3", sysDescr, sysName, client
			}
		}
		client.Close()
	}

	return false, "", "", "", "", nil
}

func (s *CLIScanner) testSNMPWithFallback(ip string) SNMPVersionResult {
	port := uint16(161)

	// Strategy: Try v3 first if configured, then fallback to v2c communities
	versionsToTry := []string{}

	// Determine versions to try based on configuration
	if s.config.Version == 3 && s.config.Username != "" {
		versionsToTry = append(versionsToTry, "v3")
	}

	// Always try v2c if:
	// 1. Explicitly requested, OR
	// 2. v3 not properly configured, OR
	// 3. Fallback is enabled (default behavior)
	if s.config.Version == 2 || s.config.Version == 1 || s.config.Version == 0 || s.config.Username == "" {
		versionsToTry = append(versionsToTry, "v2c")
	}

	// Try each version until we get a successful response
	for _, version := range versionsToTry {
		if s.config.Verbose {
			fmt.Printf("🔍 Trying SNMP %s on %s...\n", version, ip)
		}

		switch version {
		case "v3":
			result := s.trySNMPv3(ip, port)
			if result.Success {
				if s.config.Verbose {
					fmt.Printf("✅ SNMPv3 successful on %s\n", ip)
				}
				return result
			}
			if s.config.Verbose {
				fmt.Printf("❌ SNMPv3 failed on %s: %s\n", ip, result.ErrorMessage)
			}

		case "v2c":
			result := s.trySNMPv2cWithCommunities(ip, port)
			if result.Success {
				if s.config.Verbose {
					fmt.Printf("✅ SNMPv2c successful on %s with community '%s'\n", ip, result.Community)
				}
				return result
			}
			if s.config.Verbose {
				fmt.Printf("❌ SNMPv2c failed on %s: %s\n", ip, result.ErrorMessage)
			}
		}
	}

	// All versions failed
	return SNMPVersionResult{
		Success:      false,
		ErrorMessage: "All SNMP versions failed",
	}
}

// trySNMPv3 attempts SNMPv3 authentication
func (s *CLIScanner) trySNMPv3(ip string, port uint16) SNMPVersionResult {
	client := snmp.NewSNMPv3Client(
		ip, port,
		s.config.Username,
		s.config.AuthKey,
		s.config.PrivKey,
	)

	client.AuthProtocol = snmp.AuthProtocolFromString(s.config.AuthProtocol)
	client.PrivProtocol = snmp.PrivProtocolFromString(s.config.PrivProtocol)
	client.Timeout = s.config.Timeout
	client.Retries = s.config.Retries

	if err := client.Connect(); err != nil {
		return SNMPVersionResult{
			Success:      false,
			ErrorMessage: fmt.Sprintf("v3 connect failed: %v", err),
		}
	}

	sysDescr, err := client.TestConnection()
	if err != nil {
		client.Close()
		return SNMPVersionResult{
			Success:      false,
			ErrorMessage: fmt.Sprintf("v3 test failed: %v", err),
		}
	}

	sysName, _ := client.Get("1.3.6.1.2.1.1.5.0")

	return SNMPVersionResult{
		Success:  true,
		Version:  "SNMPv3",
		Username: s.config.Username,
		SysDescr: sysDescr,
		SysName:  sysName,
		Client:   client,
	}
}

// trySNMPv2cWithCommunities attempts SNMPv2c with multiple community strings
func (s *CLIScanner) trySNMPv2cWithCommunities(ip string, port uint16) SNMPVersionResult {
	// Build list of communities to try
	communitiesToTry := make([]string, 0, len(s.config.Communities)+1)

	// Add other communities if not already included
	for _, community := range s.config.Communities {
		communitiesToTry = append(communitiesToTry, community)
	}

	// Try each community
	for _, community := range communitiesToTry {
		client := snmp.NewClient(ip, port)
		client.Community = community
		client.Version = 1 // SNMPv2c
		client.Timeout = s.config.Timeout
		client.Retries = s.config.Retries

		if err := client.Connect(); err != nil {
			client.Close()
			continue
		}

		sysDescr, err := client.TestConnection()
		if err != nil {
			client.Close()
			continue
		}

		sysName, _ := client.Get("1.3.6.1.2.1.1.5.0")

		return SNMPVersionResult{
			Success:   true,
			Version:   "SNMPv2c",
			Community: community,
			SysDescr:  sysDescr,
			SysName:   sysName,
			Client:    client,
		}
	}

	return SNMPVersionResult{
		Success:      false,
		ErrorMessage: "All v2c communities failed",
	}
}

// YAMLOIDCollector handles intelligent OID collection based on YAML configuration
type YAMLOIDCollector struct {
	client       *snmp.Client
	config       *VendorFingerprintConfig
	vendorLogger *VendorDetectionLogger
	timeout      time.Duration
}

func (tc *TCPPortChecker) CheckHostResponsive(ctx context.Context, ipAddress string) bool {
	// Create context with timeout
	checkCtx, cancel := context.WithTimeout(ctx, tc.timeout)
	defer cancel()

	// Create channel to receive first successful connection
	successChan := make(chan bool, 1)
	var wg sync.WaitGroup

	// Test all ports concurrently
	for _, port := range tc.ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()

			if tc.checkSinglePort(checkCtx, ipAddress, p) {
				select {
				case successChan <- true:
				default:
					// Channel already has a value, ignore
				}
			}
		}(port)
	}

	// Wait for either success or all goroutines to finish
	go func() {
		wg.Wait()
		close(successChan)
	}()

	// Wait for first success or timeout
	select {
	case success := <-successChan:
		return success
	case <-checkCtx.Done():
		return false
	}
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

// NewSmartFieldExtractor creates a new smart field extractor
func NewSmartFieldExtractor(config *VendorFingerprintConfig) *SmartFieldExtractor {
	return &SmartFieldExtractor{
		vendorConfig: config,
	}
}
