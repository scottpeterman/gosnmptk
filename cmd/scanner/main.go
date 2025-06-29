package main

import (
	"context"
	"encoding/csv"
	"fmt"
	"image/color"
	"net"
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

	// Import your existing SNMP client
	"github.com/scottpeterman/gosnmptk/pkg/snmp"
)

// CustomTheme implements fyne.Theme with your branding colors
type CustomTheme struct{}

// Color returns colors for the cyberpunk theme
func (t *CustomTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
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
func (t *CustomTheme) Font(style fyne.TextStyle) fyne.Resource {
	return theme.DefaultTheme().Font(style)
}

// Icon returns icons for the theme
func (t *CustomTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}

// Size returns sizes for the theme
func (t *CustomTheme) Size(name fyne.ThemeSizeName) float32 {
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
type CustomCard struct {
	widget.Card
}

func NewCustomCard(title, subtitle string, content fyne.CanvasObject) *CustomCard {
	card := &CustomCard{}
	card.ExtendBaseWidget(card)
	card.SetTitle(title)
	card.SetSubTitle(subtitle)
	card.SetContent(content)
	return card
}

func (c *CustomCard) CreateRenderer() fyne.WidgetRenderer {
	// Get the base renderer
	renderer := c.Card.CreateRenderer()

	// You could customize the renderer here if needed
	// For now, we'll rely on theme colors
	return renderer
}

// Enhanced button with custom styling
type CustomButton struct {
	widget.Button
	importance widget.Importance
}

func NewCustomButton(text string, tapped func()) *CustomButton {
	btn := &CustomButton{}
	btn.ExtendBaseWidget(btn)
	btn.SetText(text)
	btn.OnTapped = tapped
	return btn
}

func (b *CustomButton) SetImportance(importance widget.Importance) {
	b.importance = importance
	b.Refresh()
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
	Communities  []string
	Username     string
	AuthProtocol string
	AuthKey      string
	PrivProtocol string
	PrivKey      string
	Timeout      time.Duration
	Retries      int
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

// testSNMP tests SNMP connectivity using your existing client with proper cleanup
func (ns *NetworkScanner) testSNMP(ip string) (bool, string, string, string, string) {
	port := uint16(161)

	// Try SNMPv2c communities first
	for _, community := range ns.snmpConfig.Communities {
		// Create client
		client := snmp.NewClient(ip, port)
		client.Community = community
		client.Version = 1 // SNMPv2c
		client.Timeout = ns.snmpConfig.Timeout
		client.Retries = ns.snmpConfig.Retries

		// Test connection
		if err := client.Connect(); err != nil {
			client.Close() // Always close, even on connection failure
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

		client.Close() // Important: always close
		return true, community, "SNMPv2c", sysDescr, sysName
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
				client.Close()
				return true, ns.snmpConfig.Username, "SNMPv3", sysDescr, sysName
			}
			client.Close()
		}
	}

	return false, "", "", "", ""
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

// scanHost scans a single host with real SNMP testing and proper cleanup
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
		snmpReady, community, version, sysDescr, sysName := ns.testSNMP(ip)
		result.SNMPReady = snmpReady
		result.SNMPCommunity = community
		result.SNMPVersion = version
		result.SystemDescr = sysDescr
		result.SystemName = sysName

		// Use SNMP sysName as hostname if available and more descriptive
		if sysName != "" && sysName != ip && len(sysName) > len(result.Hostname) {
			result.Hostname = sysName
		}
	}

	return result
}

// ScanNetwork scans a network range with proper cleanup
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

	// Collect results with timeout protection
	collectTimeout := time.After(10 * time.Minute) // Max scan time

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
			// Timeout protection
			if ns.onComplete != nil {
				ns.onComplete()
			}
			return fmt.Errorf("scan timeout exceeded")
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
	app    fyne.App
	window fyne.Window

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

	// Status display
	progressBar  *widget.ProgressBar
	statusLabel  *widget.Label
	statsLabel   *widget.Label
	resultsTable *widget.Table

	// Controls
	scanButton   *widget.Button
	cancelButton *widget.Button
	exportButton *widget.Button
	clearButton  *widget.Button

	// Scanner
	scanner *NetworkScanner

	// Results
	results []ScanResult
	mu      sync.RWMutex
}

// NewNetworkScannerApp creates a new enhanced scanner application
func NewNetworkScannerApp() *NetworkScannerApp {
	// Create app with custom theme
	app := app.NewWithID("gosnmp-network-scanner-enhanced")
	app.Settings().SetTheme(&CustomTheme{})
	app.SetIcon(theme.ComputerIcon())

	window := app.NewWindow("Go SNMP Network Scanner - Enhanced")
	window.Resize(fyne.NewSize(1400, 900))

	return &NetworkScannerApp{
		app:     app,
		window:  window,
		scanner: NewNetworkScanner(),
		results: make([]ScanResult, 0),
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

	// Enhanced results table with more columns
	app.resultsTable = widget.NewTable(
		func() (int, int) {
			app.mu.RLock()
			defer app.mu.RUnlock()
			return len(app.results) + 1, 8 // +1 for header, 8 columns
		},
		func() fyne.CanvasObject {
			return widget.NewLabel("")
		},
		func(id widget.TableCellID, obj fyne.CanvasObject) {
			label := obj.(*widget.Label)

			if id.Row == 0 {
				// Header
				headers := []string{"IP", "Hostname", "Status", "RTT", "SNMP", "Version", "Community/User", "Description"}
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
					label.SetText(result.IP)
				case 1:
					label.SetText(result.Hostname)
				case 2:
					if result.Responding {
						label.SetText("✅ Up")
					} else {
						label.SetText("❌ Down")
					}
				case 3:
					if result.Responding {
						label.SetText(fmt.Sprintf("%.1fms", float64(result.RTT.Nanoseconds())/1000000))
					} else {
						label.SetText("-")
					}
				case 4:
					if result.SNMPReady {
						label.SetText("✅ Ready")
					} else if result.Responding {
						label.SetText("❌ No SNMP")
					} else {
						label.SetText("-")
					}
				case 5:
					label.SetText(result.SNMPVersion)
				case 6:
					label.SetText(result.SNMPCommunity)
				case 7:
					// Truncate system description
					desc := result.SystemDescr
					if len(desc) > 50 {
						desc = desc[:50] + "..."
					}
					label.SetText(desc)
				}
			}
		},
	)

	// Set column widths
	app.resultsTable.SetColumnWidth(0, 120) // IP
	app.resultsTable.SetColumnWidth(1, 180) // Hostname
	app.resultsTable.SetColumnWidth(2, 70)  // Status
	app.resultsTable.SetColumnWidth(3, 70)  // RTT
	app.resultsTable.SetColumnWidth(4, 80)  // SNMP
	app.resultsTable.SetColumnWidth(5, 80)  // Version
	app.resultsTable.SetColumnWidth(6, 120) // Community/User
	app.resultsTable.SetColumnWidth(7, 350) // Description

	// Setup scanner callbacks
	app.scanner.SetProgressCallback(app.updateProgress)
	app.scanner.SetResultCallback(app.addResult)
	app.scanner.SetCompleteCallback(app.scanComplete)
}

// createLayout creates the enhanced application layout
func (app *NetworkScannerApp) createLayout() fyne.CanvasObject {
	// Basic configuration form
	basicForm := &widget.Form{
		Items: []*widget.FormItem{
			{Text: "Network CIDR", Widget: app.networkEntry},
			{Text: "Timeout (seconds)", Widget: app.timeoutEntry},
			{Text: "Max Concurrent", Widget: app.concurrencyEntry},
		},
	}

	// SNMP configuration
	snmpForm := &widget.Form{
		Items: []*widget.FormItem{
			{Text: "SNMPv2c Communities", Widget: app.communitiesEntry},
			{Text: "SNMPv3 Username", Widget: app.usernameEntry},
			{Text: "Auth Protocol", Widget: app.authProtocolSelect},
			{Text: "Auth Key", Widget: app.authKeyEntry},
			{Text: "Priv Protocol", Widget: app.privProtocolSelect},
			{Text: "Priv Key", Widget: app.privKeyEntry},
		},
	}

	// Use custom cards for better styling
	basicCard := NewCustomCard("Basic Configuration", "", basicForm)
	snmpCard := NewCustomCard("SNMP Configuration", "", snmpForm)

	// Controls
	controlsContainer := container.NewHBox(
		app.scanButton,
		app.cancelButton,
		widget.NewSeparator(),
		app.exportButton,
		app.clearButton,
	)

	// Status panel
	statusContainer := container.NewVBox(
		app.statusLabel,
		app.progressBar,
		app.statsLabel,
	)

	statusCard := NewCustomCard("Scan Status", "", statusContainer)

	// Top panel
	topPanel := container.NewVBox(
		container.NewHBox(basicCard, snmpCard),
		statusCard,
	)

	// Results panel
	resultsCard := NewCustomCard("Enhanced Scan Results", "",
		container.NewBorder(
			controlsContainer, nil, nil, nil,
			container.NewScroll(app.resultsTable),
		),
	)

	// Main layout
	return container.NewBorder(
		topPanel, nil, nil, nil,
		resultsCard,
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

	// Configure scanner
	app.scanner.SetTimeout(time.Duration(timeoutSecs * float64(time.Second)))
	app.scanner.SetConcurrency(concurrency)

	snmpConfig := SNMPConfig{
		Communities:  communities,
		Username:     strings.TrimSpace(app.usernameEntry.Text),
		AuthProtocol: app.authProtocolSelect.Selected,
		AuthKey:      strings.TrimSpace(app.authKeyEntry.Text),
		PrivProtocol: app.privProtocolSelect.Selected,
		PrivKey:      strings.TrimSpace(app.privKeyEntry.Text),
		Timeout:      2 * time.Second,
		Retries:      1,
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
	app.mu.Lock()
	app.results = append(app.results, result)
	app.mu.Unlock()

	app.resultsTable.Refresh()
}

// scanComplete handles scan completion
func (app *NetworkScannerApp) scanComplete() {
	app.scanButton.Enable()
	app.cancelButton.Disable()

	app.mu.RLock()
	hasResults := len(app.results) > 0
	app.mu.RUnlock()

	if hasResults {
		app.exportButton.Enable()
		app.clearButton.Enable()
	}

	stats := app.scanner.GetStats()
	app.statusLabel.SetText(fmt.Sprintf("Enhanced scan complete! %d hosts scanned in %v",
		stats.Scanned, stats.ElapsedTime.Truncate(time.Second)))

	app.progressBar.SetValue(1.0)
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
	}
	if err := csvWriter.Write(header); err != nil {
		return err
	}

	// Write enhanced data
	app.mu.RLock()
	defer app.mu.RUnlock()

	for _, result := range app.results {
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
		}

		if err := csvWriter.Write(record); err != nil {
			return err
		}
	}

	return nil
}

// Run starts the enhanced application
func (app *NetworkScannerApp) Run() {
	app.initializeUI()
	app.window.SetContent(app.createLayout())
	app.window.ShowAndRun()
}

func main() {
	app := NewNetworkScannerApp()
	app.Run()
}
