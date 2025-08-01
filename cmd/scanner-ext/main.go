package main

import (
	"context"
	"encoding/csv"
	"fmt"
	"image/color"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	// Import your existing SNMP client and fingerprint library
	_ "github.com/scottpeterman/gosnmptk/internal/resources"
	"github.com/scottpeterman/gosnmptk/pkg/fingerprint"
	"github.com/scottpeterman/gosnmptk/pkg/persistence"
	"github.com/scottpeterman/gosnmptk/pkg/snmp"
)

// CyberpunkTheme implements fyne.Theme with cyberpunk colors
type CyberpunkTheme struct{}

const (
	// Network settings
	PrefKeyNetwork     = "scanner.network"
	PrefKeyTimeout     = "scanner.timeout"
	PrefKeyConcurrency = "scanner.concurrency"

	// SNMP settings
	PrefKeyCommunities  = "scanner.communities"
	PrefKeyUsername     = "scanner.username"
	PrefKeyAuthProtocol = "scanner.auth_protocol"
	PrefKeyAuthKey      = "scanner.auth_key"
	PrefKeyPrivProtocol = "scanner.priv_protocol"
	PrefKeyPrivKey      = "scanner.priv_key"

	// Advanced settings
	PrefKeyEnableFingerprint = "scanner.enable_fingerprint"
	PrefKeyFingerprintType   = "scanner.fingerprint_type"
	PrefKeyEnablePersist     = "scanner.enable_persist"
	PrefKeyDBPath            = "scanner.db_path"
)

// Default settings struct
type ScannerDefaults struct {
	Network           string
	Timeout           string
	Concurrency       string
	Communities       string
	Username          string
	AuthProtocol      string
	AuthKey           string
	PrivProtocol      string
	PrivKey           string
	EnableFingerprint bool
	FingerprintType   string
	EnablePersist     bool
	DBPath            string
}

var scannerDefaultSettings = ScannerDefaults{
	Network:           "10.1.0.0/24",
	Timeout:           "3",
	Concurrency:       "25",
	Communities:       "public,private",
	Username:          "",
	AuthProtocol:      "SHA",
	AuthKey:           "",
	PrivProtocol:      "AES128",
	PrivKey:           "",
	EnableFingerprint: false,
	FingerprintType:   "basic",
	EnablePersist:     false,
	DBPath:            "./scanner_devices.json",
}

// Color returns colors for the cyberpunk theme
func (t *CyberpunkTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	switch name {
	// Background colors - Pure black cyberpunk aesthetic
	case theme.ColorNameBackground:
		return color.NRGBA{R: 0x00, G: 0x00, B: 0x00, A: 0xFF} // #000000
	case theme.ColorNameOverlayBackground:
		return color.NRGBA{R: 0x00, G: 0x00, B: 0x00, A: 0xF2} // panel_bg with alpha
	case theme.ColorNameMenuBackground:
		return color.NRGBA{R: 0x00, G: 0x00, B: 0x00, A: 0xFF} // darker_bg

	// Text colors - Bright cyan for that cyberpunk glow
	case theme.ColorNameForeground:
		return color.NRGBA{R: 0x22, G: 0xD3, B: 0xEE, A: 0xFF} // #22D3EE
	case theme.ColorNameDisabled:
		return color.NRGBA{R: 0x22, G: 0xD3, B: 0xEE, A: 0x80} // muted cyan
	case theme.ColorNamePlaceHolder:
		return color.NRGBA{R: 0x22, G: 0xD3, B: 0xEE, A: 0x66} // semi-transparent cyan

	// Button colors - Dark with cyan highlights
	case theme.ColorNameButton:
		return color.NRGBA{R: 0x00, G: 0x1A, B: 0x1F, A: 0xFF} // lighter_bg
	case theme.ColorNameHover:
		return color.NRGBA{R: 0x00, G: 0x1A, B: 0x1F, A: 0xFF} // button_hover
	case theme.ColorNamePressed:
		return color.NRGBA{R: 0x00, G: 0x0D, B: 0x10, A: 0xFF} // button_pressed

	// Primary/accent colors - Bright cyan theme
	case theme.ColorNamePrimary:
		return color.NRGBA{R: 0x22, G: 0xD3, B: 0xEE, A: 0xFF} // line color
	case theme.ColorNameFocus:
		return color.NRGBA{R: 0x0E, G: 0xA5, B: 0xE9, A: 0xFF} // success color
	case theme.ColorNameSelection:
		return color.NRGBA{R: 0x22, G: 0xD3, B: 0xEE, A: 0x33} // selected_bg

	// Input field colors
	case theme.ColorNameInputBackground:
		return color.NRGBA{R: 0x00, G: 0x1A, B: 0x1F, A: 0xFF} // lighter_bg
	case theme.ColorNameInputBorder:
		return color.NRGBA{R: 0x22, G: 0xD3, B: 0xEE, A: 0x66} // border_light

	// Scroll and separator colors
	case theme.ColorNameScrollBar:
		return color.NRGBA{R: 0x22, G: 0xD3, B: 0xEE, A: 0x4D} // scrollbar thumb
	case theme.ColorNameSeparator:
		return color.NRGBA{R: 0x22, G: 0xD3, B: 0xEE, A: 0x1A} // grid color

	// Status colors - Cyberpunk palette
	case theme.ColorNameSuccess:
		return color.NRGBA{R: 0x0E, G: 0xA5, B: 0xE9, A: 0xFF} // success
	case theme.ColorNameWarning:
		return color.NRGBA{R: 0x22, G: 0xD3, B: 0xEE, A: 0xFF} // cyan warning
	case theme.ColorNameError:
		return color.NRGBA{R: 0xDC, G: 0x26, B: 0x26, A: 0xFF} // error

	// Shadow and outline
	case theme.ColorNameShadow:
		return color.NRGBA{R: 0x22, G: 0xD3, B: 0xEE, A: 0x1A} // cyan shadow
	case theme.ColorNameHeaderBackground:
		return color.NRGBA{R: 0x00, G: 0x00, B: 0x00, A: 0xFF} // pure black
	}

	// Fallback to default theme for unhandled colors
	return theme.DefaultTheme().Color(name, variant)
}

// Font returns fonts for the theme
func (t *CyberpunkTheme) Font(style fyne.TextStyle) fyne.Resource {
	return theme.DefaultTheme().Font(style)
}

// Icon returns icons for the theme
func (t *CyberpunkTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}

// Size returns sizes for the theme
func (t *CyberpunkTheme) Size(name fyne.ThemeSizeName) float32 {
	switch name {
	case theme.SizeNamePadding:
		return 8
	case theme.SizeNameInlineIcon:
		return 20
	case theme.SizeNameInnerPadding:
		return 4
	case theme.SizeNameLineSpacing:
		return 4
	case theme.SizeNameScrollBar:
		return 16
	case theme.SizeNameScrollBarSmall:
		return 8
	case theme.SizeNameSeparatorThickness:
		return 1
	case theme.SizeNameInputBorder:
		return 2
	case theme.SizeNameInputRadius:
		return 4
	case theme.SizeNameSelectionRadius:
		return 3
	}

	return theme.DefaultTheme().Size(name)
}

// Enhanced card widget with custom styling
type CyberpunkCard struct {
	widget.Card
}

func NewCyberpunkCard(title, subtitle string, content fyne.CanvasObject) *CyberpunkCard {
	card := &CyberpunkCard{}
	card.ExtendBaseWidget(card)
	card.SetTitle(title)
	card.SetSubTitle(subtitle)
	card.SetContent(content)
	return card
}

func (c *CyberpunkCard) CreateRenderer() fyne.WidgetRenderer {
	// Get the base renderer
	renderer := c.Card.CreateRenderer()

	// You could customize the renderer here if needed
	// For now, we'll rely on theme colors
	return renderer
}

// ScanResult represents the result of scanning a single host
type ScanResult struct {
	IP            string        `json:"ip"`
	Hostname      string        `json:"hostname"`
	Responding    bool          `json:"responding"`
	RTT           time.Duration `json:"rtt"`
	SNMPReady     bool          `json:"snmp_ready"`
	SNMPCommunity string        `json:"snmp_community,omitempty"`
	SNMPVersion   string        `json:"snmp_version,omitempty"`
	SystemDescr   string        `json:"system_descr,omitempty"`
	SystemName    string        `json:"system_name,omitempty"`
	Error         string        `json:"error,omitempty"`
	ScanTime      time.Time     `json:"scan_time"`

	// Enhanced fingerprinting fields
	FingerprintPerformed bool              `json:"fingerprint_performed"`
	DetectedVendor       string            `json:"detected_vendor,omitempty"`
	VendorConfidence     string            `json:"vendor_confidence,omitempty"`
	VendorMethod         string            `json:"vendor_method,omitempty"`
	VendorData           map[string]string `json:"vendor_data,omitempty"`
	FingerprintError     string            `json:"fingerprint_error,omitempty"`
}

// ScanStats holds scanning statistics
type ScanStats struct {
	Total       int64
	Scanned     int64
	Responding  int64
	SNMPReady   int64
	Errors      int64
	StartTime   time.Time
	ElapsedTime time.Duration
}

// SNMPConfig holds SNMP configuration
type SNMPConfig struct {
	Communities          []string
	Username             string
	AuthProtocol         string
	AuthKey              string
	PrivProtocol         string
	PrivKey              string
	Timeout              time.Duration
	Retries              int
	EnableFingerprinting bool
	FingerprintType      string // "basic" or "full"
}

// NetworkScanner handles network scanning operations with real SNMP testing
type NetworkScanner struct {
	// Configuration
	timeout     time.Duration
	concurrency int
	snmpConfig  SNMPConfig

	// State
	ctx     context.Context
	cancel  context.CancelFunc
	results []ScanResult
	stats   ScanStats
	mu      sync.RWMutex

	// Callbacks for UI updates
	onProgress func(stats ScanStats)
	onResult   func(result ScanResult)
	onComplete func()
}

// NewNetworkScanner creates a new network scanner with SNMP integration
func NewNetworkScanner() *NetworkScanner {
	return &NetworkScanner{
		timeout:     3 * time.Second,
		concurrency: 25, // Conservative for real SNMP testing
		snmpConfig: SNMPConfig{
			Communities:  []string{"public", "private"},
			AuthProtocol: "SHA",
			PrivProtocol: "AES128",
			Timeout:      2 * time.Second,
			Retries:      1,
		},
		results: make([]ScanResult, 0),
	}
}

// SetTimeout sets the connectivity timeout
func (ns *NetworkScanner) SetTimeout(timeout time.Duration) {
	ns.timeout = timeout
}

// SetConcurrency sets the maximum concurrent operations
func (ns *NetworkScanner) SetConcurrency(concurrency int) {
	ns.concurrency = concurrency
}

// SetSNMPConfig sets SNMP configuration
func (ns *NetworkScanner) SetSNMPConfig(config SNMPConfig) {
	ns.snmpConfig = config
}

// SetProgressCallback sets the progress update callback
func (ns *NetworkScanner) SetProgressCallback(callback func(ScanStats)) {
	ns.onProgress = callback
}

// SetResultCallback sets the result callback
func (ns *NetworkScanner) SetResultCallback(callback func(ScanResult)) {
	ns.onResult = callback
}

// SetCompleteCallback sets the completion callback
func (ns *NetworkScanner) SetCompleteCallback(callback func()) {
	ns.onComplete = callback
}

// generateIPs generates IP addresses from CIDR notation
func (ns *NetworkScanner) generateIPs(cidr string) ([]string, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}

	var ips []string
	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}

	// Remove network and broadcast addresses for subnets smaller than /31
	ones, _ := ipNet.Mask.Size()
	if ones < 31 && len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}

	return ips, nil
}

// inc increments an IP address
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// testConnectivity performs basic connectivity check
func (ns *NetworkScanner) testConnectivity(ip string) (bool, time.Duration, error) {
	start := time.Now()

	// Try common TCP ports for faster connectivity check
	ports := []string{"80", "443", "22", "23", "161", "8080"}
	for _, port := range ports {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, port), ns.timeout/time.Duration(len(ports)))
		if err == nil {
			conn.Close()
			return true, time.Since(start), nil
		}
	}

	return false, time.Since(start), fmt.Errorf("no services responding")
}

// performFingerprinting performs vendor fingerprinting on a device
func (ns *NetworkScanner) performFingerprinting(client *snmp.Client, result *ScanResult) {
	if !ns.snmpConfig.EnableFingerprinting {
		return
	}

	// Create fingerprint client
	fpClient := fingerprint.NewClient(client)
	fpClient.SetTimeout(5 * time.Second) // Shorter timeout for GUI

	ctx := context.Background()

	var fpResult *fingerprint.FingerprintResult
	var err error

	if ns.snmpConfig.FingerprintType == "basic" {
		fpResult, err = fpClient.QuickVendorDetection()
	} else {
		fpResult, err = fpClient.PerformFingerprinting(ctx, "auto-detect")
	}

	result.FingerprintPerformed = true

	if err != nil {
		result.FingerprintError = err.Error()
		return
	}

	if fpResult != nil {
		result.DetectedVendor = fpResult.DetectedVendor
		result.VendorConfidence = fpResult.Confidence
		result.VendorMethod = fpResult.DetectionMethod
		result.VendorData = fpResult.FingerprintData
	}
}

// testSNMP tests SNMP connectivity using your existing client with proper cleanup
func (ns *NetworkScanner) testSNMP(ip string) (bool, string, string, string, string, *snmp.Client) {
	port := uint16(161)

	// Try SNMPv2c communities first
	for _, community := range ns.snmpConfig.Communities {
		client := snmp.NewClient(ip, port)
		client.Community = community
		client.Version = 1 // SNMPv2c
		client.Timeout = ns.snmpConfig.Timeout
		client.Retries = ns.snmpConfig.Retries

		if err := client.Connect(); err != nil {
			client.Close()
			continue
		}

		// Test with sysDescr
		sysDescr, err := client.TestConnection()
		if err != nil {
			client.Close()
			continue
		}

		// Get sysName for hostname
		sysName, _ := client.Get("1.3.6.1.2.1.1.5.0")

		// Don't close client here - return it for potential fingerprinting
		return true, community, "SNMPv2c", sysDescr, sysName, client
	}

	// Try SNMPv3 if configured
	if ns.snmpConfig.Username != "" {
		client := snmp.NewSNMPv3Client(
			ip, port,
			ns.snmpConfig.Username,
			ns.snmpConfig.AuthKey,
			ns.snmpConfig.PrivKey,
		)

		// Set protocols
		client.AuthProtocol = snmp.AuthProtocolFromString(ns.snmpConfig.AuthProtocol)
		client.PrivProtocol = snmp.PrivProtocolFromString(ns.snmpConfig.PrivProtocol)
		client.Timeout = ns.snmpConfig.Timeout
		client.Retries = ns.snmpConfig.Retries

		if err := client.Connect(); err == nil {
			if sysDescr, err := client.TestConnection(); err == nil {
				sysName, _ := client.Get("1.3.6.1.2.1.1.5.0")
				// Don't close client here - return it for potential fingerprinting
				return true, ns.snmpConfig.Username, "SNMPv3", sysDescr, sysName, client
			}
			client.Close()
		}
	}

	return false, "", "", "", "", nil
}

// lookupHostname performs reverse DNS lookup with timeout
func (ns *NetworkScanner) lookupHostname(ip string) string {
	// Use a timeout for DNS lookup
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ip
	}
	return strings.TrimSuffix(names[0], ".")
}

// scanHost scans a single host with real SNMP testing and optional fingerprinting
func (ns *NetworkScanner) scanHost(ip string) ScanResult {
	result := ScanResult{
		IP:       ip,
		Hostname: ip,
		ScanTime: time.Now(),
	}

	// Check if scan was cancelled
	select {
	case <-ns.ctx.Done():
		result.Error = "scan cancelled"
		return result
	default:
	}

	// Check basic connectivity first
	responding, rtt, err := ns.testConnectivity(ip)
	result.Responding = responding
	result.RTT = rtt

	if err != nil {
		result.Error = err.Error()
	}

	if responding {
		// Get hostname via DNS (with timeout)
		result.Hostname = ns.lookupHostname(ip)

		// Test SNMP with real client
		snmpReady, community, version, sysDescr, sysName, client := ns.testSNMP(ip)
		result.SNMPReady = snmpReady
		result.SNMPCommunity = community
		result.SNMPVersion = version
		result.SystemDescr = sysDescr
		result.SystemName = sysName

		// Use SNMP sysName as hostname if available and more descriptive
		if sysName != "" && sysName != ip && len(sysName) > len(result.Hostname) {
			result.Hostname = sysName
		}

		// Perform fingerprinting if enabled and SNMP is ready
		if client != nil {
			ns.performFingerprinting(client, &result)
			client.Close() // Close after fingerprinting
		}
	}

	return result
}

// ScanNetwork scans a network range with dynamic timeout based on network size
func (ns *NetworkScanner) ScanNetwork(cidr string) error {

	// Clean up any previous scan first
	if ns.cancel != nil {
		ns.cancel()
		time.Sleep(200 * time.Millisecond) // Wait for cleanup
	}

	// Generate IPs
	ips, err := ns.generateIPs(cidr)
	if err != nil {
		return err
	}

	// Initialize context and stats
	ns.ctx, ns.cancel = context.WithCancel(context.Background())

	// Reset stats completely
	ns.mu.Lock()
	ns.stats = ScanStats{
		Total:      int64(len(ips)),
		StartTime:  time.Now(),
		Scanned:    0,
		Responding: 0,
		SNMPReady:  0,
		Errors:     0,
	}
	ns.results = make([]ScanResult, 0, len(ips))
	ns.mu.Unlock()

	// Create semaphore for concurrency control
	sem := make(chan struct{}, ns.concurrency)
	resultChan := make(chan ScanResult, ns.concurrency) // Smaller buffer

	// Start workers
	var wg sync.WaitGroup
	for _, ip := range ips {
		select {
		case <-ns.ctx.Done():
			break
		default:
		}

		wg.Add(1)
		go func(ipAddr string) {
			defer wg.Done()

			// Acquire semaphore
			select {
			case sem <- struct{}{}:
			case <-ns.ctx.Done():
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
			case <-ns.ctx.Done():
				return
			default:
			}

			// Scan host
			result := ns.scanHost(ipAddr)

			select {
			case resultChan <- result:
			case <-ns.ctx.Done():
				return
			}
		}(ip)
	}

	// Close result channel when all workers complete
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// ENHANCED: Dynamic timeout based on network size
	var maxScanTime time.Duration
	ipCount := len(ips)

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

	// Log the timeout being used (optional)
	if ns.onProgress != nil {
		// You could add this info to ScanStats if desired
		fmt.Printf("Scanning %d IPs with timeout of %v\n", ipCount, maxScanTime)
	}

	// Collect results with dynamic timeout protection
	collectTimeout := time.After(maxScanTime)

	for {
		select {
		case result, ok := <-resultChan:
			if !ok {
				// Channel closed, all done
				if ns.onComplete != nil {
					ns.onComplete()
				}
				return nil
			}

			ns.mu.Lock()
			ns.results = append(ns.results, result)

			// Update stats
			atomic.AddInt64(&ns.stats.Scanned, 1)
			if result.Responding {
				atomic.AddInt64(&ns.stats.Responding, 1)
			}
			if result.SNMPReady {
				atomic.AddInt64(&ns.stats.SNMPReady, 1)
			}
			if result.Error != "" {
				atomic.AddInt64(&ns.stats.Errors, 1)
			}

			ns.stats.ElapsedTime = time.Since(ns.stats.StartTime)
			stats := ns.stats
			ns.mu.Unlock()

			// Notify UI
			if ns.onResult != nil {
				ns.onResult(result)
			}
			if ns.onProgress != nil {
				ns.onProgress(stats)
			}

		case <-ns.ctx.Done():
			// Cancelled
			if ns.onComplete != nil {
				ns.onComplete()
			}
			return context.Canceled

		case <-collectTimeout:
			// Timeout protection - now with appropriate timeouts
			if ns.onComplete != nil {
				ns.onComplete()
			}
			return fmt.Errorf("scan timeout exceeded after %v (%d IPs)", maxScanTime, ipCount)
		}
	}
}

// Cancel stops the scanning process and cleans up resources
func (ns *NetworkScanner) Cancel() {
	if ns.cancel != nil {
		ns.cancel()
	}
	// Allow time for goroutines to cleanup
	time.Sleep(100 * time.Millisecond)
}

// GetResults returns current results
func (ns *NetworkScanner) GetResults() []ScanResult {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	return append([]ScanResult(nil), ns.results...)
}

// GetStats returns current statistics
func (ns *NetworkScanner) GetStats() ScanStats {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	return ns.stats
}

// NetworkScannerApp represents the enhanced GUI application

type NetworkScannerApp struct {
	app         fyne.App
	window      fyne.Window
	dbPathTimer *time.Timer
	dbPathMutex sync.Mutex
	// UI Components
	networkEntry     *widget.Entry
	timeoutEntry     *widget.Entry
	concurrencyEntry *widget.Entry
	communitiesEntry *widget.Entry

	// SNMPv3 fields
	usernameEntry      *widget.Entry
	authProtocolSelect *widget.Select
	authKeyEntry       *widget.Entry
	privProtocolSelect *widget.Select
	privKeyEntry       *widget.Entry

	// Fingerprinting options
	enableFingerprintCheck *widget.Check
	fingerprintTypeSelect  *widget.Select

	// Status display
	progressBar  *widget.ProgressBar
	statusLabel  *widget.Label
	statsLabel   *widget.Label
	resultsTable *widget.Table

	// Controls
	scanButton                *widget.Button
	cancelButton              *widget.Button
	exportButton              *widget.Button
	clearButton               *widget.Button
	fingerprintSelectedButton *widget.Button

	// ADD THESE: Persistence components
	persistenceBridge  *persistence.PersistenceBridge
	enablePersistCheck *widget.Check
	dbPathEntry        *widget.Entry
	aggregateButton    *widget.Button
	aggregateTable     *widget.Table
	aggregateResults   []persistence.Device
	aggregateMutex     sync.RWMutex

	// Scanner
	scanner *NetworkScanner

	// Results
	results []ScanResult
	mu      sync.RWMutex
}

// NewNetworkScannerApp creates a new enhanced scanner application

func NewNetworkScannerApp() *NetworkScannerApp {
	// Create app with cyberpunk theme
	app := app.NewWithID("gosnmp-network-scanner-enhanced")
	app.Settings().SetTheme(&CyberpunkTheme{})
	app.SetIcon(theme.ComputerIcon())

	window := app.NewWindow("Go SNMP Network Scanner - Enhanced with Persistence")
	window.Resize(fyne.NewSize(1800, 1200)) // Larger for aggregate view

	// Initialize persistence (disabled by default with empty path)
	persistenceBridge := persistence.NewPersistenceBridge("", false) // FIXED: Empty path, disabled

	return &NetworkScannerApp{
		app:               app,
		window:            window,
		scanner:           NewNetworkScanner(),
		results:           make([]ScanResult, 0),
		persistenceBridge: persistenceBridge,
		aggregateResults:  make([]persistence.Device, 0),
	}
}

// initializeUI initializes the enhanced user interface

func (app *NetworkScannerApp) initializeUI() {
	// Input fields
	app.networkEntry = widget.NewEntry()
	app.networkEntry.SetPlaceHolder("10.1.0.0/16")

	app.timeoutEntry = widget.NewEntry()
	app.timeoutEntry.SetText("3")

	app.concurrencyEntry = widget.NewEntry()
	app.concurrencyEntry.SetText("25")

	app.communitiesEntry = widget.NewEntry()
	app.communitiesEntry.SetText("public,private")

	// SNMPv3 fields
	app.usernameEntry = widget.NewEntry()
	app.usernameEntry.SetPlaceHolder("SNMPv3 username (optional)")

	app.authProtocolSelect = widget.NewSelect(
		[]string{"None", "MD5", "SHA", "SHA224", "SHA256", "SHA384", "SHA512"},
		nil,
	)
	app.authProtocolSelect.SetSelected("SHA")

	app.authKeyEntry = widget.NewEntry()
	app.authKeyEntry.SetPlaceHolder("Auth key (optional)")
	app.authKeyEntry.Password = true

	app.privProtocolSelect = widget.NewSelect(
		[]string{"None", "DES", "AES128", "AES192", "AES256"},
		nil,
	)
	app.privProtocolSelect.SetSelected("AES128")

	app.privKeyEntry = widget.NewEntry()
	app.privKeyEntry.SetPlaceHolder("Priv key (optional)")
	app.privKeyEntry.Password = true

	// Fingerprinting options
	app.enableFingerprintCheck = widget.NewCheck("Enable vendor fingerprinting", nil)
	app.fingerprintTypeSelect = widget.NewSelect(
		[]string{"basic", "full"},
		nil,
	)
	app.fingerprintTypeSelect.SetSelected("basic")

	// Persistence UI components
	app.enablePersistCheck = widget.NewCheck("Enable Device Persistence", app.onPersistenceToggle)
	app.enablePersistCheck.SetChecked(false)

	app.dbPathEntry = widget.NewEntry()
	app.dbPathEntry.SetText("./scanner_devices.json")
	app.dbPathEntry.Disable() // Initially disabled

	app.aggregateButton = widget.NewButton("View Device Database", app.showAggregateView)
	app.aggregateButton.Disable()

	// Status components
	app.progressBar = widget.NewProgressBar()
	app.statusLabel = widget.NewLabel("Ready to scan")
	app.statsLabel = widget.NewLabel("")

	// Controls
	app.scanButton = widget.NewButton("Start Enhanced Scan", app.startScan)
	app.scanButton.Importance = widget.HighImportance

	app.cancelButton = widget.NewButton("Cancel", app.cancelScan)
	app.cancelButton.Disable()

	app.exportButton = widget.NewButton("Export Results", app.exportResults)
	app.exportButton.Disable()

	app.clearButton = widget.NewButton("Clear Results", app.clearResults)
	app.clearButton.Disable()

	app.fingerprintSelectedButton = widget.NewButton("Fingerprint Selected", app.fingerprintSelected)
	app.fingerprintSelectedButton.Disable()

	// Enhanced results table with persistence column
	app.resultsTable = widget.NewTable(
		func() (int, int) {
			app.mu.RLock()
			defer app.mu.RUnlock()
			return len(app.results) + 1, 11 // +1 for header, 11 columns (added persistence column)
		},
		func() fyne.CanvasObject {
			return widget.NewLabel("")
		},
		func(id widget.TableCellID, obj fyne.CanvasObject) {
			label := obj.(*widget.Label)

			if id.Row == 0 {
				// Header - MODIFIED to include persistence column
				headers := []string{"Select", "IP", "Hostname", "Status", "RTT", "SNMP", "Version", "Vendor", "Confidence", "Description", "Stored"}
				if id.Col < len(headers) {
					label.SetText(headers[id.Col])
					label.TextStyle.Bold = true
				}
				return
			}

			app.mu.RLock()
			defer app.mu.RUnlock()

			if id.Row-1 < len(app.results) {
				result := app.results[id.Row-1]

				switch id.Col {
				case 0:
					if result.SNMPReady {
						label.SetText("☐") // Checkbox placeholder
					} else {
						label.SetText("")
					}
				case 1:
					label.SetText(result.IP)
				case 2:
					label.SetText(result.Hostname)
				case 3:
					if result.Responding {
						label.SetText("✅ Up")
					} else {
						label.SetText("❌ Down")
					}
				case 4:
					if result.Responding {
						label.SetText(fmt.Sprintf("%.1fms", float64(result.RTT.Nanoseconds())/1000000))
					} else {
						label.SetText("-")
					}
				case 5:
					if result.SNMPReady {
						label.SetText("✅ Ready")
					} else if result.Responding {
						label.SetText("❌ No SNMP")
					} else {
						label.SetText("-")
					}
				case 6:
					label.SetText(result.SNMPVersion)
				case 7:
					if result.FingerprintPerformed {
						vendor := result.DetectedVendor
						if vendor == "" {
							vendor = "unknown"
						}
						label.SetText(vendor)
					} else {
						label.SetText("-")
					}
				case 8:
					if result.FingerprintPerformed {
						label.SetText(result.VendorConfidence)
					} else {
						label.SetText("-")
					}
				case 9:
					// Truncate system description
					desc := result.SystemDescr
					if len(desc) > 40 {
						desc = desc[:40] + "..."
					}
					label.SetText(desc)
				case 10: // NEW: Persistence status column
					if app.persistenceBridge != nil && app.enablePersistCheck.Checked {
						label.SetText("💾") // Saved to database
					} else {
						label.SetText("-")
					}
				}
			}
		},
	)

	// Set column widths including new persistence column
	app.resultsTable.SetColumnWidth(0, 50)  // Select
	app.resultsTable.SetColumnWidth(1, 120) // IP
	app.resultsTable.SetColumnWidth(2, 180) // Hostname
	app.resultsTable.SetColumnWidth(3, 70)  // Status
	app.resultsTable.SetColumnWidth(4, 70)  // RTT
	app.resultsTable.SetColumnWidth(5, 80)  // SNMP
	app.resultsTable.SetColumnWidth(6, 80)  // Version
	app.resultsTable.SetColumnWidth(7, 100) // Vendor
	app.resultsTable.SetColumnWidth(8, 80)  // Confidence
	app.resultsTable.SetColumnWidth(9, 300) // Description
	app.resultsTable.SetColumnWidth(10, 60) // Stored

	// Setup scanner callbacks
	app.scanner.SetProgressCallback(app.updateProgress)
	app.scanner.SetResultCallback(app.addResult)
	app.scanner.SetCompleteCallback(app.scanComplete)

	// NEW: Load saved settings AFTER widgets are created
	app.loadSettings()

}

// loadSettings loads all settings from preferences

func (app *NetworkScannerApp) loadSettings() {
	prefs := app.app.Preferences()

	// Load network settings
	app.networkEntry.SetText(prefs.StringWithFallback(PrefKeyNetwork, scannerDefaultSettings.Network))
	app.timeoutEntry.SetText(prefs.StringWithFallback(PrefKeyTimeout, scannerDefaultSettings.Timeout))
	app.concurrencyEntry.SetText(prefs.StringWithFallback(PrefKeyConcurrency, scannerDefaultSettings.Concurrency))

	// Load SNMP settings
	app.communitiesEntry.SetText(prefs.StringWithFallback(PrefKeyCommunities, scannerDefaultSettings.Communities))
	app.usernameEntry.SetText(prefs.StringWithFallback(PrefKeyUsername, scannerDefaultSettings.Username))
	app.authProtocolSelect.SetSelected(prefs.StringWithFallback(PrefKeyAuthProtocol, scannerDefaultSettings.AuthProtocol))
	app.authKeyEntry.SetText(prefs.StringWithFallback(PrefKeyAuthKey, scannerDefaultSettings.AuthKey))
	app.privProtocolSelect.SetSelected(prefs.StringWithFallback(PrefKeyPrivProtocol, scannerDefaultSettings.PrivProtocol))
	app.privKeyEntry.SetText(prefs.StringWithFallback(PrefKeyPrivKey, scannerDefaultSettings.PrivKey))

	// Load advanced settings
	app.enableFingerprintCheck.SetChecked(prefs.BoolWithFallback(PrefKeyEnableFingerprint, scannerDefaultSettings.EnableFingerprint))
	app.fingerprintTypeSelect.SetSelected(prefs.StringWithFallback(PrefKeyFingerprintType, scannerDefaultSettings.FingerprintType))
	app.enablePersistCheck.SetChecked(prefs.BoolWithFallback(PrefKeyEnablePersist, scannerDefaultSettings.EnablePersist))
	app.dbPathEntry.SetText(prefs.StringWithFallback(PrefKeyDBPath, scannerDefaultSettings.DBPath))

	// Set up UI state based on persistence checkbox (but don't create database yet)
	// app.onPersistenceToggle(app.enablePersistCheck.Checked)
}

// saveSettings saves current settings to preferences
func (app *NetworkScannerApp) saveSettings() {
	prefs := app.app.Preferences()

	// Save network settings
	prefs.SetString(PrefKeyNetwork, app.networkEntry.Text)
	prefs.SetString(PrefKeyTimeout, app.timeoutEntry.Text)
	prefs.SetString(PrefKeyConcurrency, app.concurrencyEntry.Text)

	// Save SNMP settings
	prefs.SetString(PrefKeyCommunities, app.communitiesEntry.Text)
	prefs.SetString(PrefKeyUsername, app.usernameEntry.Text)
	prefs.SetString(PrefKeyAuthProtocol, app.authProtocolSelect.Selected)
	prefs.SetString(PrefKeyAuthKey, app.authKeyEntry.Text)
	prefs.SetString(PrefKeyPrivProtocol, app.privProtocolSelect.Selected)
	prefs.SetString(PrefKeyPrivKey, app.privKeyEntry.Text)

	// Save advanced settings
	prefs.SetBool(PrefKeyEnableFingerprint, app.enableFingerprintCheck.Checked)
	prefs.SetString(PrefKeyFingerprintType, app.fingerprintTypeSelect.Selected)
	prefs.SetBool(PrefKeyEnablePersist, app.enablePersistCheck.Checked)
	prefs.SetString(PrefKeyDBPath, app.dbPathEntry.Text)
}

// createLayout creates the application layout with proper proportions
func (app *NetworkScannerApp) createLayout() fyne.CanvasObject {
	// Set consistent entry field sizes
	app.timeoutEntry.Resize(fyne.NewSize(60, 0))
	app.concurrencyEntry.Resize(fyne.NewSize(60, 0))

	// === NETWORK CONFIGURATION CARD (Compact) ===
	networkContent := container.NewVBox(
		// Network CIDR - full width
		container.NewBorder(nil, nil,
			widget.NewLabel("Network CIDR:"), nil,
			app.networkEntry,
		),
		// Timeout and concurrency in a clean row
		container.NewGridWithColumns(2,
			container.NewVBox(
				widget.NewLabel("Timeout:"),
				container.NewHBox(app.timeoutEntry, widget.NewLabel("sec")),
			),
			container.NewVBox(
				widget.NewLabel("Max Concurrent:"),
				app.concurrencyEntry,
			),
		),
	)

	// === SNMP AUTHENTICATION CARD ===
	snmpContent := container.NewVBox(
		// Communities - full width
		container.NewBorder(nil, nil,
			widget.NewLabel("Communities:"), nil,
			app.communitiesEntry,
		),
		// Username - full width
		container.NewBorder(nil, nil,
			widget.NewLabel("SNMPv3 Username:"), nil,
			app.usernameEntry,
		),
		// Auth settings - protocol gets 30%, key gets 70%
		container.NewVBox(
			widget.NewLabel("Authentication:"),
			container.NewBorder(nil, nil,
				container.NewHBox(
					app.authProtocolSelect,
					widget.NewLabel("Key:"),
				),
				nil,
				app.authKeyEntry,
			),
		),
		// Priv settings - protocol gets 30%, key gets 70%
		container.NewVBox(
			widget.NewLabel("Privacy:"),
			container.NewBorder(nil, nil,
				container.NewHBox(
					app.privProtocolSelect,
					widget.NewLabel("Key:"),
				),
				nil,
				app.privKeyEntry,
			),
		),
	)

	// === ADVANCED OPTIONS CARD ===
	advancedContent := container.NewVBox(
		// Fingerprinting toggle and type
		container.NewVBox(
			app.enableFingerprintCheck,
			container.NewBorder(nil, nil,
				widget.NewLabel("Type:"), nil,
				app.fingerprintTypeSelect,
			),
		),
		widget.NewSeparator(),
		// Persistence toggle and path
		container.NewVBox(
			app.enablePersistCheck,
			container.NewBorder(nil, nil,
				widget.NewLabel("DB Path:"), nil,
				app.dbPathEntry,
			),
		),
	)

	// === CREATE THE THREE CARDS ===
	networkCard := NewCyberpunkCard("Network", "", networkContent)
	snmpCard := NewCyberpunkCard("SNMP Authentication                 ", "", snmpContent)
	advancedCard := NewCyberpunkCard("Advanced Options", "", advancedContent)

	// === PROPORTIONAL WIDTH CONFIGURATION ROW (Alternative Method) ===
	// Set explicit sizes to control proportions better
	networkCard.Resize(fyne.NewSize(250, 0))  // Smaller width for network
	snmpCard.Resize(fyne.NewSize(400, 0))     // Medium width for SNMP
	advancedCard.Resize(fyne.NewSize(400, 0)) // Medium width for advanced

	configRow := container.NewHBox(networkCard, snmpCard, advancedCard)

	// === STATUS BAR ===
	thinStatusBar := container.NewBorder(
		nil, nil,
		app.statusLabel,
		app.statsLabel,
		app.progressBar,
	)

	// === TOP SECTION ===
	topSection := container.NewVBox(
		configRow,
		thinStatusBar,
	)

	// === CONTROL BUTTONS ===
	controlsContainer := container.NewHBox(
		app.scanButton,
		app.cancelButton,
		widget.NewSeparator(),
		app.exportButton,
		app.clearButton,
		widget.NewSeparator(),
		app.fingerprintSelectedButton,
		widget.NewSeparator(),
		app.aggregateButton,
	)

	// === RESULTS SECTION ===
	resultsContainer := container.NewBorder(
		controlsContainer, nil, nil, nil,
		container.NewScroll(app.resultsTable),
	)

	// === FINAL LAYOUT ===
	return container.NewBorder(
		topSection, nil, nil, nil,
		resultsContainer,
	)
}

// startScan starts the enhanced network scanning process

func (app *NetworkScannerApp) startScan() {
	// Validate inputs
	network := strings.TrimSpace(app.networkEntry.Text)
	if network == "" {
		dialog.ShowError(fmt.Errorf("please enter a network CIDR"), app.window)
		return
	}

	// Parse timeout
	timeoutStr := strings.TrimSpace(app.timeoutEntry.Text)
	timeoutSecs, err := strconv.ParseFloat(timeoutStr, 64)
	if err != nil || timeoutSecs <= 0 {
		dialog.ShowError(fmt.Errorf("invalid timeout value"), app.window)
		return
	}

	// Parse concurrency
	concurrencyStr := strings.TrimSpace(app.concurrencyEntry.Text)
	concurrency, err := strconv.Atoi(concurrencyStr)
	if err != nil || concurrency <= 0 || concurrency > 100 {
		dialog.ShowError(fmt.Errorf("concurrency must be between 1 and 100"), app.window)
		return
	}

	// Parse communities
	communitiesStr := strings.TrimSpace(app.communitiesEntry.Text)
	var communities []string
	if communitiesStr != "" {
		communities = strings.Split(communitiesStr, ",")
		for i, community := range communities {
			communities[i] = strings.TrimSpace(community)
		}
	}

	// NEW: Apply persistence settings now that we're starting a scan
	if err := app.applyPersistenceSettings(); err != nil {
		dialog.ShowError(fmt.Errorf("failed to set up persistence: %v", err), app.window)
		return
	}

	// Configure scanner
	app.scanner.SetTimeout(time.Duration(timeoutSecs * float64(time.Second)))
	app.scanner.SetConcurrency(concurrency)

	snmpConfig := SNMPConfig{
		Communities:          communities,
		Username:             strings.TrimSpace(app.usernameEntry.Text),
		AuthProtocol:         app.authProtocolSelect.Selected,
		AuthKey:              strings.TrimSpace(app.authKeyEntry.Text),
		PrivProtocol:         app.privProtocolSelect.Selected,
		PrivKey:              strings.TrimSpace(app.privKeyEntry.Text),
		Timeout:              2 * time.Second,
		Retries:              1,
		EnableFingerprinting: app.enableFingerprintCheck.Checked,
		FingerprintType:      app.fingerprintTypeSelect.Selected,
	}
	app.scanner.SetSNMPConfig(snmpConfig)

	// Clear previous results if not already cleared
	app.mu.Lock()
	app.results = make([]ScanResult, 0)
	app.mu.Unlock()
	app.resultsTable.Refresh()

	// Update UI state
	app.scanButton.Disable()
	app.cancelButton.Enable()
	app.exportButton.Disable()
	app.clearButton.Disable()
	app.progressBar.SetValue(0)
	app.statusLabel.SetText("Starting enhanced scan...")

	// Start scan in goroutine
	go func() {
		err := app.scanner.ScanNetwork(network)
		if err != nil && err != context.Canceled {
			dialog.ShowError(err, app.window)
		}
		// scanComplete will be called by the scanner
	}()
}

// cancelScan cancels the current scan
func (app *NetworkScannerApp) cancelScan() {
	app.scanner.Cancel()
	app.statusLabel.SetText("Cancelling scan...")
}

// clearResults clears the scan results
func (app *NetworkScannerApp) clearResults() {
	app.mu.Lock()
	app.results = make([]ScanResult, 0)
	app.mu.Unlock()
	app.resultsTable.Refresh()
	app.clearButton.Disable()
	app.exportButton.Disable()
	app.statusLabel.SetText("Results cleared")
	app.statsLabel.SetText("")
	app.progressBar.SetValue(0)
}

// updateProgress updates the progress display
func (app *NetworkScannerApp) updateProgress(stats ScanStats) {
	if stats.Total > 0 {
		progress := float64(stats.Scanned) / float64(stats.Total)
		app.progressBar.SetValue(progress)

		app.statusLabel.SetText(fmt.Sprintf("Scanning... %d/%d (%.1f%%)",
			stats.Scanned, stats.Total, progress*100))

		app.statsLabel.SetText(fmt.Sprintf(
			"Responding: %d | SNMP Ready: %d | Elapsed: %v",
			stats.Responding, stats.SNMPReady, stats.ElapsedTime.Truncate(time.Second)))
	}
}

// addResult adds a scan result to the table

func (app *NetworkScannerApp) addResult(result ScanResult) {
	// FILTER: Only process hosts that are responding (Up)
	if !result.Responding {
		return // Skip down hosts completely
	}

	app.mu.Lock()
	app.results = append(app.results, result)
	app.mu.Unlock()

	// Record to persistence if enabled (only responding hosts)
	if app.persistenceBridge != nil && app.enablePersistCheck.Checked {
		app.recordScanResultToPersistence(result)
	}

	app.resultsTable.Refresh()
}

// fingerprintSelected performs fingerprinting on selected SNMP-ready devices
func (app *NetworkScannerApp) fingerprintSelected() {
	app.mu.RLock()
	var snmpReadyDevices []ScanResult
	for _, result := range app.results {
		if result.SNMPReady && !result.FingerprintPerformed {
			snmpReadyDevices = append(snmpReadyDevices, result)
		}
	}
	app.mu.RUnlock()

	if len(snmpReadyDevices) == 0 {
		dialog.ShowInformation("No Devices", "No SNMP-ready devices found that haven't been fingerprinted.", app.window)
		return
	}

	// Confirm fingerprinting
	dialog.ShowConfirm("Fingerprint Devices",
		fmt.Sprintf("Perform vendor fingerprinting on %d SNMP-ready devices?\n\nThis may take a few minutes.", len(snmpReadyDevices)),
		func(confirmed bool) {
			if confirmed {
				app.performBatchFingerprinting(snmpReadyDevices)
			}
		}, app.window)
}

// performBatchFingerprinting performs fingerprinting on a batch of devices
func (app *NetworkScannerApp) performBatchFingerprinting(devices []ScanResult) {
	app.fingerprintSelectedButton.Disable()
	app.statusLabel.SetText("Performing vendor fingerprinting...")

	go func() {
		defer func() {
			app.fingerprintSelectedButton.Enable()
			app.scanComplete()
		}()

		for i, device := range devices {
			app.statusLabel.SetText(fmt.Sprintf("Fingerprinting %d/%d: %s", i+1, len(devices), device.IP))

			// Create SNMP client for this device
			var client *snmp.Client
			if device.SNMPVersion == "SNMPv3" {
				client = snmp.NewSNMPv3Client(
					device.IP, 161,
					app.scanner.snmpConfig.Username,
					app.scanner.snmpConfig.AuthKey,
					app.scanner.snmpConfig.PrivKey,
				)
				client.AuthProtocol = snmp.AuthProtocolFromString(app.scanner.snmpConfig.AuthProtocol)
				client.PrivProtocol = snmp.PrivProtocolFromString(app.scanner.snmpConfig.PrivProtocol)
			} else {
				client = snmp.NewClient(device.IP, 161)
				client.Community = device.SNMPCommunity
				client.Version = 1
			}

			client.Timeout = 5 * time.Second
			client.Retries = 1

			if err := client.Connect(); err != nil {
				continue
			}

			// Update the device in results
			app.mu.Lock()
			for j := range app.results {
				if app.results[j].IP == device.IP {
					app.scanner.performFingerprinting(client, &app.results[j])
					break
				}
			}
			app.mu.Unlock()

			client.Close()
			app.resultsTable.Refresh()

			// Small delay between devices
			time.Sleep(500 * time.Millisecond)
		}

		app.statusLabel.SetText(fmt.Sprintf("Fingerprinting complete! Processed %d devices", len(devices)))
	}()
}

// scanComplete handles scan completion

func (app *NetworkScannerApp) scanComplete() {
	app.scanButton.Enable()
	app.cancelButton.Disable()

	app.mu.RLock()
	hasResults := len(app.results) > 0
	var snmpCount, fingerprintCount, persistedCount int
	for _, result := range app.results {
		if result.SNMPReady {
			snmpCount++
		}
		if result.FingerprintPerformed {
			fingerprintCount++
		}
		if app.persistenceBridge != nil && app.enablePersistCheck.Checked {
			persistedCount++
		}
	}
	app.mu.RUnlock()

	if hasResults {
		app.exportButton.Enable()
		app.clearButton.Enable()

		// Enable fingerprint button if there are SNMP devices without fingerprinting
		if snmpCount > fingerprintCount {
			app.fingerprintSelectedButton.Enable()
		}
	}

	stats := app.scanner.GetStats()
	statusMsg := fmt.Sprintf("Scan complete! %d hosts scanned in %v", stats.Scanned, stats.ElapsedTime.Truncate(time.Second))

	if fingerprintCount > 0 {
		statusMsg += fmt.Sprintf(" (%d fingerprinted)", fingerprintCount)
	}

	// NEW: Show persistence summary
	if persistedCount > 0 {
		statusMsg += fmt.Sprintf(" (%d stored in database)", persistedCount)
	}

	app.statusLabel.SetText(statusMsg)
	app.progressBar.SetValue(1.0)

	// NEW: Update aggregate view if it's open
	if app.aggregateTable != nil {
		app.loadAggregateDevices()
		app.aggregateTable.Refresh()
	}
}

// exportResults exports enhanced scan results
func (app *NetworkScannerApp) exportResults() {
	dialog.ShowFileSave(func(writer fyne.URIWriteCloser, err error) {
		if err != nil || writer == nil {
			return
		}
		defer writer.Close()

		if err := app.saveResultsCSV(writer); err != nil {
			dialog.ShowError(err, app.window)
		} else {
			dialog.ShowInformation("Export Complete",
				fmt.Sprintf("Enhanced results exported to %s", writer.URI().Name()),
				app.window)
		}
	}, app.window)
}

// saveResultsCSV saves enhanced results to CSV format
func (app *NetworkScannerApp) saveResultsCSV(writer fyne.URIWriteCloser) error {
	csvWriter := csv.NewWriter(writer)
	defer csvWriter.Flush()

	// Write enhanced header
	header := []string{
		"IP", "Hostname", "Responding", "RTT_ms", "SNMP_Ready",
		"SNMP_Version", "SNMP_Community", "System_Description",
		"System_Name", "Error", "Scan_Time",
		"Fingerprint_Performed", "Detected_Vendor", "Vendor_Confidence",
		"Vendor_Method", "Vendor_Model", "Vendor_Serial", "Vendor_Version",
	}
	if err := csvWriter.Write(header); err != nil {
		return err
	}

	// Write enhanced data
	app.mu.RLock()
	defer app.mu.RUnlock()

	for _, result := range app.results {
		// Extract vendor data for common fields
		var vendorModel, vendorSerial, vendorVersion string
		if result.VendorData != nil {
			// Look for common vendor fields
			for key, value := range result.VendorData {
				keyLower := strings.ToLower(key)
				if strings.Contains(keyLower, "model") || strings.Contains(keyLower, "product") {
					vendorModel = value
				} else if strings.Contains(keyLower, "serial") || strings.Contains(keyLower, "service tag") {
					vendorSerial = value
				} else if strings.Contains(keyLower, "version") || strings.Contains(keyLower, "firmware") {
					vendorVersion = value
				}
			}
		}

		record := []string{
			result.IP,
			result.Hostname,
			fmt.Sprintf("%t", result.Responding),
			fmt.Sprintf("%.1f", float64(result.RTT.Nanoseconds())/1000000),
			fmt.Sprintf("%t", result.SNMPReady),
			result.SNMPVersion,
			result.SNMPCommunity,
			result.SystemDescr,
			result.SystemName,
			result.Error,
			result.ScanTime.Format(time.RFC3339),
			fmt.Sprintf("%t", result.FingerprintPerformed),
			result.DetectedVendor,
			result.VendorConfidence,
			result.VendorMethod,
			vendorModel,
			vendorSerial,
			vendorVersion,
		}

		if err := csvWriter.Write(record); err != nil {
			return err
		}
	}

	return nil
}

// onPersistenceToggle handles persistence enable/disable - FIXED to use user input
func (app *NetworkScannerApp) onPersistenceToggle(checked bool) {
	if checked {
		// Enable UI elements but don't create database yet
		app.dbPathEntry.Enable()
		app.aggregateButton.Enable()
		app.statusLabel.SetText("Persistence will be enabled on next scan")
	} else {
		// Disable persistence immediately and close any existing bridge
		if app.persistenceBridge != nil {
			app.persistenceBridge.Close()
			app.persistenceBridge = persistence.NewPersistenceBridge("", false)
		}

		app.dbPathEntry.Disable()
		app.aggregateButton.Disable()
		app.statusLabel.SetText("Persistence disabled")
	}

	// REMOVED: app.saveSettings() - Let user save manually
	// REMOVED: app.resultsTable.Refresh() - Not needed here

	// Give user feedback about unsaved changes
	app.statusLabel.SetText("Settings changed - use Settings > Save Settings to persist")
}

// ADD a function to check for unsaved changes (optional)

func (app *NetworkScannerApp) hasUnsavedChanges() bool {
	prefs := app.app.Preferences()

	// Check if current UI values differ from saved preferences
	return (app.networkEntry.Text != prefs.StringWithFallback(PrefKeyNetwork, scannerDefaultSettings.Network) ||
		app.timeoutEntry.Text != prefs.StringWithFallback(PrefKeyTimeout, scannerDefaultSettings.Timeout) ||
		app.concurrencyEntry.Text != prefs.StringWithFallback(PrefKeyConcurrency, scannerDefaultSettings.Concurrency) ||
		app.communitiesEntry.Text != prefs.StringWithFallback(PrefKeyCommunities, scannerDefaultSettings.Communities) ||
		app.usernameEntry.Text != prefs.StringWithFallback(PrefKeyUsername, scannerDefaultSettings.Username) ||
		app.authProtocolSelect.Selected != prefs.StringWithFallback(PrefKeyAuthProtocol, scannerDefaultSettings.AuthProtocol) ||
		app.authKeyEntry.Text != prefs.StringWithFallback(PrefKeyAuthKey, scannerDefaultSettings.AuthKey) ||
		app.privProtocolSelect.Selected != prefs.StringWithFallback(PrefKeyPrivProtocol, scannerDefaultSettings.PrivProtocol) ||
		app.privKeyEntry.Text != prefs.StringWithFallback(PrefKeyPrivKey, scannerDefaultSettings.PrivKey) ||
		app.enableFingerprintCheck.Checked != prefs.BoolWithFallback(PrefKeyEnableFingerprint, scannerDefaultSettings.EnableFingerprint) ||
		app.fingerprintTypeSelect.Selected != prefs.StringWithFallback(PrefKeyFingerprintType, scannerDefaultSettings.FingerprintType) ||
		app.enablePersistCheck.Checked != prefs.BoolWithFallback(PrefKeyEnablePersist, scannerDefaultSettings.EnablePersist) ||
		app.dbPathEntry.Text != prefs.StringWithFallback(PrefKeyDBPath, scannerDefaultSettings.DBPath))
}

func (app *NetworkScannerApp) applyPersistenceSettings() error {
	// Only set up persistence if the checkbox is checked
	if !app.enablePersistCheck.Checked {
		// Make sure persistence is disabled
		if app.persistenceBridge != nil {
			app.persistenceBridge.Close()
			app.persistenceBridge = persistence.NewPersistenceBridge("", false)
		}
		return nil
	}

	// Get the database path
	dbPath := strings.TrimSpace(app.dbPathEntry.Text)
	if dbPath == "" {
		dbPath = "./scanner_devices.json"
		app.dbPathEntry.SetText(dbPath)
	}

	// Close existing bridge if any
	if app.persistenceBridge != nil {
		app.persistenceBridge.Close()
	}

	// Create new persistence bridge with user-specified path
	app.persistenceBridge = persistence.NewPersistenceBridge(dbPath, true)

	// Load existing devices for display
	app.loadAggregateDevices()

	app.statusLabel.SetText("Persistence enabled: " + dbPath)
	return nil
}

// setupMenu creates the application menu
func (app *NetworkScannerApp) setupMenu() {
	// Settings menu with manual save option
	saveSettingsItem := fyne.NewMenuItem("Save Settings", func() {
		app.saveSettings()
		app.statusLabel.SetText("Settings saved successfully")
	})

	viewSettingsItem := fyne.NewMenuItem("View Current Settings", func() {
		app.showSettingsInfo()
	})

	clearSettingsItem := fyne.NewMenuItem("Clear Settings", func() {
		app.showClearSettingsDialog()
	})

	settingsMenu := fyne.NewMenu("Settings",
		saveSettingsItem, // NEW: Manual save option
		fyne.NewMenuItemSeparator(),
		viewSettingsItem,
		clearSettingsItem)

	// File menu
	exitItem := fyne.NewMenuItem("Exit", func() {
		app.app.Quit()
	})

	fileMenu := fyne.NewMenu("File", exitItem)

	// Help menu
	aboutItem := fyne.NewMenuItem("About", func() {
		dialog.ShowInformation("About",
			"Go SNMP Network Scanner - Enhanced\nVersion 1.0.0\n\nCyberpunk-themed network discovery tool with persistence",
			app.window)
	})

	helpMenu := fyne.NewMenu("Help", aboutItem)

	// Create main menu
	mainMenu := fyne.NewMainMenu(fileMenu, settingsMenu, helpMenu)
	app.window.SetMainMenu(mainMenu)
}

// showSettingsInfo displays current settings
func (app *NetworkScannerApp) showSettingsInfo() {
	prefs := app.app.Preferences()

	settingsInfo := fmt.Sprintf(`**Current Scanner Settings:**

**Network:**
- CIDR: %s
- Timeout: %s
- Max Concurrent: %s

**SNMP:**
- Communities: %s
- Username: %s
- Auth Protocol: %s
- Priv Protocol: %s

**Advanced:**
- Fingerprinting: %t (%s)
- Persistence: %t
- Database Path: %s

---
*Note: Passwords are not displayed for security*`,
		prefs.StringWithFallback(PrefKeyNetwork, "not set"),
		prefs.StringWithFallback(PrefKeyTimeout, "not set"),
		prefs.StringWithFallback(PrefKeyConcurrency, "not set"),
		prefs.StringWithFallback(PrefKeyCommunities, "not set"),
		prefs.StringWithFallback(PrefKeyUsername, "not set"),
		prefs.StringWithFallback(PrefKeyAuthProtocol, "not set"),
		prefs.StringWithFallback(PrefKeyPrivProtocol, "not set"),
		prefs.BoolWithFallback(PrefKeyEnableFingerprint, false),
		prefs.StringWithFallback(PrefKeyFingerprintType, "not set"),
		prefs.BoolWithFallback(PrefKeyEnablePersist, false),
		prefs.StringWithFallback(PrefKeyDBPath, "not set"),
	)

	content := widget.NewRichTextFromMarkdown(settingsInfo)
	content.Wrapping = fyne.TextWrapWord

	scroll := container.NewScroll(content)
	scroll.SetMinSize(fyne.NewSize(500, 400))

	dialog.NewCustom("Scanner Settings", "Close", scroll, app.window).Show()
}

// showClearSettingsDialog shows confirmation dialog for clearing settings
func (app *NetworkScannerApp) showClearSettingsDialog() {
	dialog.ShowConfirm(
		"Clear Settings",
		"Are you sure you want to clear all saved scanner settings?\n\nThis will reset all fields to defaults and cannot be undone.",
		func(confirmed bool) {
			if confirmed {
				app.resetToDefaults()
			}
		},
		app.window,
	)
}

// resetToDefaults resets all settings to default values
func (app *NetworkScannerApp) resetToDefaults() {
	prefs := app.app.Preferences()

	// Clear all preference keys
	prefKeys := []string{
		PrefKeyNetwork, PrefKeyTimeout, PrefKeyConcurrency,
		PrefKeyCommunities, PrefKeyUsername, PrefKeyAuthProtocol,
		PrefKeyAuthKey, PrefKeyPrivProtocol, PrefKeyPrivKey,
		PrefKeyEnableFingerprint, PrefKeyFingerprintType,
		PrefKeyEnablePersist, PrefKeyDBPath,
	}

	for _, key := range prefKeys {
		prefs.RemoveValue(key)
	}

	// Reset all widgets to defaults
	app.networkEntry.SetText(scannerDefaultSettings.Network)
	app.timeoutEntry.SetText(scannerDefaultSettings.Timeout)
	app.concurrencyEntry.SetText(scannerDefaultSettings.Concurrency)
	app.communitiesEntry.SetText(scannerDefaultSettings.Communities)
	app.usernameEntry.SetText(scannerDefaultSettings.Username)
	app.authProtocolSelect.SetSelected(scannerDefaultSettings.AuthProtocol)
	app.authKeyEntry.SetText(scannerDefaultSettings.AuthKey)
	app.privProtocolSelect.SetSelected(scannerDefaultSettings.PrivProtocol)
	app.privKeyEntry.SetText(scannerDefaultSettings.PrivKey)
	app.enableFingerprintCheck.SetChecked(scannerDefaultSettings.EnableFingerprint)
	app.fingerprintTypeSelect.SetSelected(scannerDefaultSettings.FingerprintType)
	app.enablePersistCheck.SetChecked(scannerDefaultSettings.EnablePersist)
	app.dbPathEntry.SetText(scannerDefaultSettings.DBPath)

	// Trigger persistence toggle to reset state
	app.onPersistenceToggle(scannerDefaultSettings.EnablePersist)

	app.statusLabel.SetText("Settings reset to defaults")
}

// recordScanResultToPersistence converts and records scan result

func (app *NetworkScannerApp) recordScanResultToPersistence(result ScanResult) {
	// Convert ScanResult to LegacyFingerprint format
	legacyResult := persistence.LegacyFingerprint{
		IPAddress:       result.IP,
		Vendor:          result.DetectedVendor,
		DeviceType:      app.inferDeviceType(result), // Now uses YAML config
		Model:           app.extractModelFromVendorData(result.VendorData),
		SerialNumber:    app.extractSerialFromVendorData(result.VendorData),
		OSVersion:       app.extractVersionFromVendorData(result.VendorData),
		FirmwareVersion: "",
		SysObjectID:     app.extractSysObjectID(result),
		SysDescr:        result.SystemDescr,
		SNMPData:        app.convertVendorDataToSNMPData(result),
		ConfidenceScore: app.convertConfidenceToScore(result.VendorConfidence),
		DetectionMethod: result.VendorMethod,
	}

	app.persistenceBridge.RecordScanResult(legacyResult)
}

// Helper functions for data conversion

func (app *NetworkScannerApp) inferDeviceType(result ScanResult) string {
	// Use YAML config to determine device type
	if fingerprint.GlobalConfigManager != nil && fingerprint.GlobalConfigManager.GetConfig() != nil {
		config := fingerprint.GlobalConfigManager.GetConfig()

		// Get vendor config from YAML
		if vendorConfig, exists := config.Vendors[result.DetectedVendor]; exists {
			// If vendor has only one device type, use it
			if len(vendorConfig.DeviceTypes) == 1 {
				return vendorConfig.DeviceTypes[0]
			}

			// If multiple device types, try to infer from sysDescr
			deviceType := app.inferDeviceTypeFromDescription(result.SystemDescr, vendorConfig.DeviceTypes)
			if deviceType != "unknown" {
				return deviceType
			}

			// Fallback to first device type for this vendor
			if len(vendorConfig.DeviceTypes) > 0 {
				return vendorConfig.DeviceTypes[0]
			}
		}
	}

	// Fallback: try to infer from description if no YAML config
	return app.inferDeviceTypeFromDescription(result.SystemDescr, nil)
}

// Enhanced function to get device type directly from YAML config
func (app *NetworkScannerApp) getDeviceTypeFromYAML(vendor string, sysDescr string) string {
	if fingerprint.GlobalConfigManager == nil || fingerprint.GlobalConfigManager.GetConfig() == nil {
		return "unknown"
	}

	config := fingerprint.GlobalConfigManager.GetConfig()
	vendorConfig, exists := config.Vendors[vendor]
	if !exists {
		return "unknown"
	}

	// If vendor configuration specifies device types, use them
	if len(vendorConfig.DeviceTypes) == 0 {
		return "unknown"
	}

	// Single device type - use it
	if len(vendorConfig.DeviceTypes) == 1 {
		return vendorConfig.DeviceTypes[0]
	}

	// Multiple device types - try to determine from description
	return app.inferDeviceTypeFromDescription(sysDescr, vendorConfig.DeviceTypes)
}

func (app *NetworkScannerApp) inferDeviceTypeFromDescription(sysDescr string, allowedTypes []string) string {
	if sysDescr == "" {
		return "unknown"
	}

	sysDescrLower := strings.ToLower(sysDescr)

	// Define type patterns that might be found in descriptions
	typePatterns := map[string][]string{
		"switch":              {"switch", "switching"},
		"router":              {"router", "routing"},
		"firewall":            {"firewall", "security gateway", "pix", "asa"},
		"wireless":            {"wireless", "access point", "ap", "wifi"},
		"server":              {"server", "poweredge", "proliant"},
		"printer":             {"printer", "laserjet", "officejet", "deskjet"},
		"print_server":        {"ethernet multi-environment", "jetdirect", "print server"},
		"network_interface":   {"network interface", "ethernet adapter"},
		"multifunction":       {"multifunction", "all-in-one", "mfp"},
		"ups":                 {"ups", "uninterruptible", "power supply"},
		"pdu":                 {"pdu", "power distribution"},
		"storage":             {"storage", "nas", "san"},
		"access_point":        {"access point", "wireless ap"},
		"wireless_controller": {"wireless controller", "wlc"},
	}

	// Check each pattern against the description
	for deviceType, patterns := range typePatterns {
		// If allowedTypes is specified (from YAML), only check allowed types
		if allowedTypes != nil {
			allowed := false
			for _, allowedType := range allowedTypes {
				if allowedType == deviceType {
					allowed = true
					break
				}
			}
			if !allowed {
				continue
			}
		}

		// Check if any pattern matches
		for _, pattern := range patterns {
			if strings.Contains(sysDescrLower, pattern) {
				return deviceType
			}
		}
	}

	return "unknown"
}

func (app *NetworkScannerApp) extractModelFromVendorData(vendorData map[string]string) string {
	if vendorData == nil {
		return ""
	}

	for key, value := range vendorData {
		keyLower := strings.ToLower(key)
		if strings.Contains(keyLower, "model") ||
			strings.Contains(keyLower, "product") ||
			strings.Contains(keyLower, "chassis") {
			return value
		}
	}
	return ""
}

func (app *NetworkScannerApp) extractSerialFromVendorData(vendorData map[string]string) string {
	if vendorData == nil {
		return ""
	}

	for key, value := range vendorData {
		keyLower := strings.ToLower(key)
		if strings.Contains(keyLower, "serial") ||
			strings.Contains(keyLower, "service tag") {
			return value
		}
	}
	return ""
}

func (app *NetworkScannerApp) extractVersionFromVendorData(vendorData map[string]string) string {
	if vendorData == nil {
		return ""
	}

	for key, value := range vendorData {
		keyLower := strings.ToLower(key)
		if strings.Contains(keyLower, "version") ||
			strings.Contains(keyLower, "firmware") ||
			strings.Contains(keyLower, "software") {
			return value
		}
	}
	return ""
}

func (app *NetworkScannerApp) extractSysObjectID(result ScanResult) string {
	// Look for sysObjectID in vendor data
	if result.VendorData != nil {
		for key, value := range result.VendorData {
			if strings.Contains(strings.ToLower(key), "object") ||
				strings.Contains(strings.ToLower(key), "oid") {
				return value
			}
		}
	}
	return ""
}

func (app *NetworkScannerApp) convertVendorDataToSNMPData(result ScanResult) map[string]string {
	snmpData := make(map[string]string)

	// Add basic SNMP data
	if result.SystemDescr != "" {
		snmpData["1.3.6.1.2.1.1.1.0"] = result.SystemDescr
	}
	if result.SystemName != "" {
		snmpData["1.3.6.1.2.1.1.5.0"] = result.SystemName
	}

	// Add vendor-specific data
	if result.VendorData != nil {
		for key, value := range result.VendorData {
			snmpData[key] = value
		}
	}

	return snmpData
}

func (app *NetworkScannerApp) convertConfidenceToScore(confidence string) int {
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

// loadAggregateDevices loads devices from persistence for display
func (app *NetworkScannerApp) loadAggregateDevices() {
	if app.persistenceBridge == nil || !app.enablePersistCheck.Checked {
		return
	}

	devices := app.persistenceBridge.GetAggregateDevices()

	app.aggregateMutex.Lock()
	app.aggregateResults = devices
	app.aggregateMutex.Unlock()
}

// showAggregateView displays the device database window
func (app *NetworkScannerApp) showAggregateView() {
	app.loadAggregateDevices()

	// Create aggregate table
	app.aggregateTable = widget.NewTable(
		func() (int, int) {
			app.aggregateMutex.RLock()
			defer app.aggregateMutex.RUnlock()
			return len(app.aggregateResults) + 1, 8 // Header + devices, 8 columns
		},
		func() fyne.CanvasObject {
			return widget.NewLabel("")
		},
		func(id widget.TableCellID, obj fyne.CanvasObject) {
			label := obj.(*widget.Label)

			if id.Row == 0 {
				// Header
				headers := []string{"Primary IP", "All IPs", "Vendor", "Device Type", "Model", "First Seen", "Last Seen", "Scan Count"}
				if id.Col < len(headers) {
					label.SetText(headers[id.Col])
					label.TextStyle.Bold = true
				}
				return
			}

			app.aggregateMutex.RLock()
			defer app.aggregateMutex.RUnlock()

			if id.Row-1 < len(app.aggregateResults) {
				device := app.aggregateResults[id.Row-1]

				switch id.Col {
				case 0:
					label.SetText(device.PrimaryIP)
				case 1:
					if len(device.AllIPs) > 1 {
						label.SetText(fmt.Sprintf("%s +%d", device.PrimaryIP, len(device.AllIPs)-1))
					} else {
						label.SetText(device.PrimaryIP)
					}
				case 2:
					label.SetText(device.Vendor)
				case 3:
					label.SetText(device.DeviceType)
				case 4:
					label.SetText(device.Model)
				case 5:
					label.SetText(device.FirstSeen.Format("2006-01-02"))
				case 6:
					label.SetText(device.LastSeen.Format("2006-01-02"))
				case 7:
					label.SetText(fmt.Sprintf("%d", device.ScanCount))
				}
			}
		},
	)

	// Set column widths
	app.aggregateTable.SetColumnWidth(0, 120) // Primary IP
	app.aggregateTable.SetColumnWidth(1, 120) // All IPs
	app.aggregateTable.SetColumnWidth(2, 100) // Vendor
	app.aggregateTable.SetColumnWidth(3, 100) // Device Type
	app.aggregateTable.SetColumnWidth(4, 150) // Model
	app.aggregateTable.SetColumnWidth(5, 100) // First Seen
	app.aggregateTable.SetColumnWidth(6, 100) // Last Seen
	app.aggregateTable.SetColumnWidth(7, 80)  // Scan Count

	// Create aggregate view window
	aggregateWindow := app.app.NewWindow("Device Database - Aggregate View")
	aggregateWindow.Resize(fyne.NewSize(1200, 800))

	// Statistics
	stats := app.persistenceBridge.GetStatistics()
	var statsText string
	if stats != nil {
		statsText = fmt.Sprintf("Total Devices: %d | Total Sessions: %d | Avg Confidence: %.1f%%",
			stats.TotalDevices, stats.TotalSessions, stats.AvgConfidence)
	} else {
		statsText = "No statistics available"
	}

	statsLabel := widget.NewLabel(statsText)

	// Buttons
	refreshBtn := widget.NewButton("Refresh", func() {
		app.loadAggregateDevices()
		app.aggregateTable.Refresh()

		// Update stats
		stats := app.persistenceBridge.GetStatistics()
		if stats != nil {
			statsText := fmt.Sprintf("Total Devices: %d | Total Sessions: %d | Avg Confidence: %.1f%%",
				stats.TotalDevices, stats.TotalSessions, stats.AvgConfidence)
			statsLabel.SetText(statsText)
		}
	})

	exportBtn := widget.NewButton("Export Database", func() {
		app.exportAggregateData(aggregateWindow)
	})

	buttonContainer := container.NewHBox(refreshBtn, exportBtn)

	content := container.NewBorder(
		container.NewVBox(statsLabel, buttonContainer),
		nil, nil, nil,
		container.NewScroll(app.aggregateTable),
	)

	aggregateWindow.SetContent(content)
	aggregateWindow.Show()
}

// exportAggregateData exports the complete device database
func (app *NetworkScannerApp) exportAggregateData(parent fyne.Window) {
	if app.persistenceBridge == nil {
		return
	}

	jsonData, err := app.persistenceBridge.ExportToJSON()
	if err != nil {
		dialog.ShowError(err, parent)
		return
	}

	dialog.ShowFileSave(func(writer fyne.URIWriteCloser, err error) {
		if err != nil || writer == nil {
			return
		}
		defer writer.Close()

		if _, err := writer.Write(jsonData); err != nil {
			dialog.ShowError(err, parent)
		} else {
			dialog.ShowInformation("Export Complete",
				fmt.Sprintf("Device database exported to %s", writer.URI().Name()),
				parent)
		}
	}, parent)
}

// getScreenSize returns the primary screen dimensions
func getScreenSize() (width, height float32) {
	switch runtime.GOOS {
	case "windows":
		return getWindowsScreenSize()
	case "darwin": // macOS
		return getMacOSScreenSize()
	case "linux":
		return getLinuxScreenSize()
	default:
		// Fallback for unknown systems
		return 1920, 1080
	}
}

// getWindowsScreenSize gets screen size on Windows
func getWindowsScreenSize() (width, height float32) {
	cmd := exec.Command("wmic", "desktopmonitor", "get", "screenwidth,screenheight", "/format:value")
	output, err := cmd.Output()
	if err != nil {
		return 1920, 1080 // Fallback
	}

	lines := strings.Split(string(output), "\n")
	var w, h int

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ScreenWidth=") {
			if val, err := strconv.Atoi(strings.TrimPrefix(line, "ScreenWidth=")); err == nil {
				w = val
			}
		}
		if strings.HasPrefix(line, "ScreenHeight=") {
			if val, err := strconv.Atoi(strings.TrimPrefix(line, "ScreenHeight=")); err == nil {
				h = val
			}
		}
	}

	if w > 0 && h > 0 {
		return float32(w), float32(h)
	}
	return 1920, 1080 // Fallback
}

// getMacOSScreenSize gets screen size on macOS
func getMacOSScreenSize() (width, height float32) {
	cmd := exec.Command("system_profiler", "SPDisplaysDataType")
	output, err := cmd.Output()
	if err != nil {
		return 1920, 1080 // Fallback
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "Resolution:") {
			// Parse "Resolution: 3840 x 2160" format
			parts := strings.Fields(line)
			if len(parts) >= 4 {
				if w, err := strconv.Atoi(parts[1]); err == nil {
					if h, err := strconv.Atoi(parts[3]); err == nil {
						return float32(w), float32(h)
					}
				}
			}
		}
	}
	return 1920, 1080 // Fallback
}

// getLinuxScreenSize gets screen size on Linux
func getLinuxScreenSize() (width, height float32) {
	// Try xrandr first (most common)
	cmd := exec.Command("xrandr")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "*") && strings.Contains(line, "x") {
				// Parse "1920x1080" format
				parts := strings.Fields(line)
				for _, part := range parts {
					if strings.Contains(part, "x") && !strings.Contains(part, "*") {
						dims := strings.Split(part, "x")
						if len(dims) == 2 {
							if w, err := strconv.Atoi(dims[0]); err == nil {
								if h, err := strconv.Atoi(dims[1]); err == nil {
									return float32(w), float32(h)
								}
							}
						}
					}
				}
			}
		}
	}

	// Try xdpyinfo as fallback
	cmd = exec.Command("xdpyinfo")
	output, err = cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "dimensions:") {
				// Parse "dimensions: 3840x2160 pixels"
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					dims := strings.Split(parts[1], "x")
					if len(dims) == 2 {
						if w, err := strconv.Atoi(dims[0]); err == nil {
							if h, err := strconv.Atoi(dims[1]); err == nil {
								return float32(w), float32(h)
							}
						}
					}
				}
			}
		}
	}

	return 1920, 1080 // Fallback
}

func (app *NetworkScannerApp) setupAppLifecycle() {
	// Handle app-level quit events (Ctrl+C, etc.)
	app.app.Lifecycle().SetOnStopped(func() {
		// Final save before app termination
		app.saveSettings()

		// Clean shutdown of persistence
		if app.persistenceBridge != nil {
			app.persistenceBridge.Close()
		}

		// Cancel any running operations
		if app.scanner != nil {
			app.scanner.Cancel()
		}
	})
}

func (app *NetworkScannerApp) Run() {
	app.initializeUI()
	app.setupAppLifecycle()
	app.setupMenu()
	// Get actual screen dimensions
	screenWidth, screenHeight := getScreenSize()

	// Calculate 90% of actual screen size
	windowWidth := screenWidth * 0.75
	windowHeight := screenHeight * 0.70

	// Set window size and center it
	app.window.Resize(fyne.NewSize(windowWidth, windowHeight))
	app.window.CenterOnScreen()

	app.window.SetContent(app.createLayout())
	app.window.ShowAndRun()
}
func main() {
	app := NewNetworkScannerApp()

	app.Run()
}
