package main

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/scottpeterman/gosnmptk/internal/resources"
	"github.com/scottpeterman/gosnmptk/pkg/fingerprint"
	"github.com/scottpeterman/gosnmptk/pkg/snmp"
)

type AppDefaults struct {
	IP           string
	Port         string
	Timeout      string
	Retries      string
	Version      string
	Community    string
	Username     string
	AuthProtocol string
	AuthKey      string
	PrivProtocol string
	PrivKey      string
}

var defaultSettings = AppDefaults{
	IP:           "",
	Port:         "161",
	Timeout:      "5.0",
	Retries:      "2",
	Version:      "SNMPv2c",
	Community:    "public",
	Username:     "",
	AuthProtocol: "SHA",
	AuthKey:      "",
	PrivProtocol: "AES128",
	PrivKey:      "",
}

func main() {
	if err := fingerprint.InitializeFromYAML("config/vendor_fingerprints.yaml"); err != nil {
		log.Printf("Warning: Could not load YAML config: %v", err)
		log.Printf("Falling back to hardcoded vendor definitions")
	} else {
		log.Printf("Successfully loaded vendor fingerprints from YAML")
	}
	myApp := app.NewWithID("gosnmptk")
	applyCyberpunkTheme(myApp)

	myApp.SetIcon(theme.ComputerIcon())

	myWindow := myApp.NewWindow("Go SNMP Tool Kit")
	myWindow.Resize(fyne.NewSize(1000, 700))

	// Create the main application
	snmpApp := NewSNMPTestApp(myApp, myWindow)
	content := snmpApp.makeUI()

	myWindow.SetContent(content)
	myWindow.ShowAndRun()
}

type SNMPTestApp struct {
	app    fyne.App
	window fyne.Window

	// Connection fields
	ipEntry        *widget.Entry
	portEntry      *widget.Entry
	timeoutEntry   *widget.Entry
	retriesEntry   *widget.Entry
	resultMessages []string

	// SNMP Version
	versionRadio *widget.RadioGroup

	// SNMPv2c
	communityEntry *widget.Entry

	// SNMPv3
	usernameEntry      *widget.Entry
	authProtocolSelect *widget.Select
	authKeyEntry       *widget.Entry
	privProtocolSelect *widget.Select
	privKeyEntry       *widget.Entry

	// Operations
	operationRadio    *widget.RadioGroup
	oidCategorySelect *widget.Select
	oidSelect         *widget.Select
	customOIDEntry    *widget.Entry

	// Fingerprinting
	fingerprintVendorSelect *widget.Select

	// Results
	resultsText *widget.RichText

	// UI containers
	v2cCard *widget.Card
	v3Card  *widget.Card

	// SNMP client
	snmpClient *snmp.Client
}

func NewSNMPTestApp(app fyne.App, window fyne.Window) *SNMPTestApp {
	return &SNMPTestApp{
		app:            app,
		window:         window,
		resultMessages: []string{},
	}
}

func (a *SNMPTestApp) makeUI() *container.AppTabs {
	// Initialize all widgets
	a.initializeWidgets()

	// Setup menu
	a.setupMenu()

	// Create tabs
	tabs := container.NewAppTabs(
		container.NewTabItem("Connection", a.makeConnectionTab()),
		container.NewTabItem("Operations", a.makeOperationsTab()),
		container.NewTabItem("Fingerprinting", a.makeFingerprintingTab()),
		container.NewTabItem("Results", a.makeResultsTab()),
	)

	return tabs
}

// setupMenu creates the application menu
func (a *SNMPTestApp) setupMenu() {
	// File menu
	viewSettingsItem := fyne.NewMenuItem("View Current Settings", func() {
		a.showSettingsInfo()
	})

	clearSettingsItem := fyne.NewMenuItem("Clear Settings", func() {
		a.showClearSettingsDialog()
	})

	exitItem := fyne.NewMenuItem("Exit", func() {
		a.app.Quit()
	})

	fileMenu := fyne.NewMenu("File",
		viewSettingsItem,
		fyne.NewMenuItemSeparator(),
		clearSettingsItem,
		fyne.NewMenuItemSeparator(),
		exitItem,
	)

	// Help menu
	aboutItem := fyne.NewMenuItem("About", func() {
		a.showAboutDialog()
	})

	helpMenu := fyne.NewMenu("Help", aboutItem)

	// Create main menu
	mainMenu := fyne.NewMainMenu(fileMenu, helpMenu)
	a.window.SetMainMenu(mainMenu)
}

// showClearSettingsDialog shows confirmation dialog for clearing settings
func (a *SNMPTestApp) showClearSettingsDialog() {
	confirmDialog := dialog.NewConfirm(
		"Clear Settings",
		"Are you sure you want to clear all saved settings?\n\nThis will reset all connection parameters to defaults and cannot be undone.",
		func(confirmed bool) {
			if confirmed {
				a.resetToDefaults()
				a.logMessage("Settings cleared successfully", "success")
			}
		},
		a.window,
	)

	confirmDialog.SetDismissText("Cancel")
	confirmDialog.SetConfirmText("Clear Settings")
	confirmDialog.Show()
}

func (a *SNMPTestApp) showAboutDialog() {
	// Use SVG logo resource
	var logoResource fyne.Resource = resources.ResourceLogoSvg

	// Create a fixed-size container for the logo
	logoImage := widget.NewIcon(logoResource)
	logoContainer := container.NewWithoutLayout(logoImage)
	logoContainer.Resize(fyne.NewSize(120, 120))
	logoImage.Move(fyne.NewPos(0, 0))
	logoImage.Resize(fyne.NewSize(120, 120))

	// Build supported vendors list dynamically
	supportedVendorsText := "### 🔍 Supported Vendors\n"

	if fingerprint.GlobalConfigManager != nil && fingerprint.GlobalConfigManager.GetConfig() != nil {
		config := fingerprint.GlobalConfigManager.GetConfig()
		for _, vendorConfig := range config.Vendors {
			deviceTypesStr := strings.Join(vendorConfig.DeviceTypes, ", ")
			supportedVendorsText += fmt.Sprintf("- **%s** - %s\n", vendorConfig.DisplayName, deviceTypesStr)
		}
	} else {
		// Fallback if YAML not loaded
		supportedVendorsText += `- **Cisco** - IOS, NX-OS, ASA platforms
- **Dell** - iDRAC server management
- **Arista** - EOS switches
- **Aruba/HP** - ProCurve, CX, Wireless
- **HP Printers** - LaserJet, OfficeJet, DeskJet series
- **Fortinet** - FortiGate firewalls
- **Palo Alto** - PAN-OS firewalls
- **APC** - UPS systems
`
	}

	// Enhanced version info with dynamic vendor list
	versionLabel := widget.NewRichTextFromMarkdown(fmt.Sprintf(`
# Go SNMP Tool Kit

**Version:** 1.0.0  
**Build Date:** 2025

---

### 🛠 Features
- **Comprehensive SNMP Operations**: GET, GETNEXT, GETBULK, WALK
- **Multi-Vendor Fingerprinting**: Dynamic vendor support via YAML configuration
- **Protocol Support**: SNMPv2c and SNMPv3 with full crypto options
- **Device Discovery**: Smart vendor detection and device type recognition
- **Serial Processing**: Device-friendly approach for maximum compatibility
- **Extensible Configuration**: Add new vendors without code changes

---

%s

---

### 👨‍💻 Developer
**Scott Peterman**  
[GitHub Repository](https://github.com/scottpeterman/gosnmptk)

### 📄 License
MIT License - See LICENSE file for details

### 🙏 Acknowledgments
- Fyne Framework for the cross-platform GUI
- Go SNMP Libraries for protocol implementation
- Network vendor documentation and MIB specifications
`, supportedVendorsText))

	versionLabel.Wrapping = fyne.TextWrapWord

	// Create content with logo and info
	content := container.NewVBox(
		container.NewCenter(logoContainer),
		widget.NewSeparator(),
		versionLabel,
	)

	// Create scrollable container
	scroll := container.NewScroll(content)
	scroll.SetMinSize(fyne.NewSize(550, 450))

	// Create dialog
	aboutDialog := dialog.NewCustom("About Go SNMP Tool Kit", "Close", scroll, a.window)
	aboutDialog.Resize(fyne.NewSize(600, 500))
	aboutDialog.Show()
}

func (a *SNMPTestApp) resetToDefaults() {
	prefs := a.app.Preferences()

	// Clear all preference keys
	prefKeys := []string{
		PrefKeyIP, PrefKeyPort, PrefKeyTimeout, PrefKeyRetries,
		PrefKeyVersion, PrefKeyCommunity, PrefKeyUsername,
		PrefKeyAuthProtocol, PrefKeyAuthKey, PrefKeyPrivProtocol, PrefKeyPrivKey,
	}

	for _, key := range prefKeys {
		prefs.RemoveValue(key)
	}

	// Manually set all widgets to default values to ensure they clear
	a.ipEntry.SetText(defaultSettings.IP)
	a.portEntry.SetText(defaultSettings.Port)
	a.timeoutEntry.SetText(defaultSettings.Timeout)
	a.retriesEntry.SetText(defaultSettings.Retries)

	// Set version first
	a.versionRadio.SetSelected(defaultSettings.Version)

	// Clear SNMPv2c settings
	a.communityEntry.SetText(defaultSettings.Community)

	// Clear SNMPv3 settings explicitly
	a.usernameEntry.SetText(defaultSettings.Username)
	a.authProtocolSelect.SetSelected(defaultSettings.AuthProtocol)
	a.authKeyEntry.SetText(defaultSettings.AuthKey)
	a.privProtocolSelect.SetSelected(defaultSettings.PrivProtocol)
	a.privKeyEntry.SetText(defaultSettings.PrivKey)

	// Force UI refresh
	a.refreshAllWidgets()

	// Trigger version change to show/hide appropriate cards
	a.onVersionChange(defaultSettings.Version)

	a.logMessage("All settings have been reset to defaults", "success")
}

func (a *SNMPTestApp) loadSettingsWithDefaults() {
	prefs := a.app.Preferences()

	// Load basic connection settings with proper defaults
	a.ipEntry.SetText(prefs.StringWithFallback(PrefKeyIP, defaultSettings.IP))
	a.portEntry.SetText(prefs.StringWithFallback(PrefKeyPort, defaultSettings.Port))
	a.timeoutEntry.SetText(prefs.StringWithFallback(PrefKeyTimeout, defaultSettings.Timeout))
	a.retriesEntry.SetText(prefs.StringWithFallback(PrefKeyRetries, defaultSettings.Retries))

	// Load SNMP version
	version := prefs.StringWithFallback(PrefKeyVersion, defaultSettings.Version)
	a.versionRadio.SetSelected(version)

	// Load SNMPv2c settings
	a.communityEntry.SetText(prefs.StringWithFallback(PrefKeyCommunity, defaultSettings.Community))

	// Load SNMPv3 settings
	a.usernameEntry.SetText(prefs.StringWithFallback(PrefKeyUsername, defaultSettings.Username))
	a.authProtocolSelect.SetSelected(prefs.StringWithFallback(PrefKeyAuthProtocol, defaultSettings.AuthProtocol))
	a.authKeyEntry.SetText(prefs.StringWithFallback(PrefKeyAuthKey, defaultSettings.AuthKey))
	a.privProtocolSelect.SetSelected(prefs.StringWithFallback(PrefKeyPrivProtocol, defaultSettings.PrivProtocol))
	a.privKeyEntry.SetText(prefs.StringWithFallback(PrefKeyPrivKey, defaultSettings.PrivKey))
}

func (a *SNMPTestApp) refreshAllWidgets() {
	// Refresh all entry widgets
	a.ipEntry.Refresh()
	a.portEntry.Refresh()
	a.timeoutEntry.Refresh()
	a.retriesEntry.Refresh()
	a.communityEntry.Refresh()
	a.usernameEntry.Refresh()
	a.authKeyEntry.Refresh()
	a.privKeyEntry.Refresh()

	// Refresh select widgets
	a.versionRadio.Refresh()
	a.authProtocolSelect.Refresh()
	a.privProtocolSelect.Refresh()

	// Trigger version change to show/hide appropriate cards
	a.onVersionChange(a.versionRadio.Selected)
}

// showSettingsInfo displays current settings
func (a *SNMPTestApp) showSettingsInfo() {
	prefs := a.app.Preferences()

	settingsInfo := fmt.Sprintf(`**Current Settings:**

**Connection:**
- IP: %s
- Port: %s
- Timeout: %s
- Retries: %s

**SNMP Version:** %s

**SNMPv2c:**
- Community: %s

**SNMPv3:**
- Username: %s
- Auth Protocol: %s
- Priv Protocol: %s

---
*Note: Passwords are not displayed for security*`,
		prefs.StringWithFallback(PrefKeyIP, "(not set)"),
		prefs.StringWithFallback(PrefKeyPort, defaultSettings.Port),
		prefs.StringWithFallback(PrefKeyTimeout, defaultSettings.Timeout),
		prefs.StringWithFallback(PrefKeyRetries, defaultSettings.Retries),
		prefs.StringWithFallback(PrefKeyVersion, defaultSettings.Version),
		prefs.StringWithFallback(PrefKeyCommunity, defaultSettings.Community),
		prefs.StringWithFallback(PrefKeyUsername, "(not set)"),
		prefs.StringWithFallback(PrefKeyAuthProtocol, defaultSettings.AuthProtocol),
		prefs.StringWithFallback(PrefKeyPrivProtocol, defaultSettings.PrivProtocol),
	)

	content := widget.NewRichTextFromMarkdown(settingsInfo)
	content.Wrapping = fyne.TextWrapWord

	scroll := container.NewScroll(content)
	scroll.SetMinSize(fyne.NewSize(400, 300))

	dialog.NewCustom("Current Settings", "Close", scroll, a.window).Show()
}

func (a *SNMPTestApp) initializeWidgets() {
	// Connection widgets - start with empty/default values (will be populated by loadSettings)
	a.ipEntry = widget.NewEntry()
	a.portEntry = widget.NewEntry()
	a.timeoutEntry = widget.NewEntry()
	a.retriesEntry = widget.NewEntry()

	// SNMP Version
	a.versionRadio = widget.NewRadioGroup([]string{"SNMPv2c", "SNMPv3"}, a.onVersionChange)

	// SNMPv2c
	a.communityEntry = widget.NewEntry()

	// SNMPv3
	a.usernameEntry = widget.NewEntry()

	a.authProtocolSelect = widget.NewSelect(
		[]string{"None", "MD5", "SHA", "SHA224", "SHA256", "SHA384", "SHA512"},
		nil,
	)

	a.authKeyEntry = widget.NewEntry()
	a.authKeyEntry.Password = true

	a.privProtocolSelect = widget.NewSelect(
		[]string{"None", "DES", "AES128", "AES192", "AES256"},
		nil,
	)

	a.privKeyEntry = widget.NewEntry()
	a.privKeyEntry.Password = true

	// Operations
	a.operationRadio = widget.NewRadioGroup(
		[]string{"GET", "GETNEXT", "GETBULK", "WALK"},
		nil,
	)
	a.operationRadio.SetSelected("GET")

	// Dynamically build OID categories from YAML config
	categories := []string{"Common MIB-II"}

	// Add all configured vendors
	if fingerprint.GlobalConfigManager != nil && fingerprint.GlobalConfigManager.GetConfig() != nil {
		config := fingerprint.GlobalConfigManager.GetConfig()
		for _, vendorConfig := range config.Vendors {
			categories = append(categories, vendorConfig.DisplayName)
		}
	} else {
		// Fallback to hardcoded list if YAML not loaded
		categories = append(categories, []string{"Dell iDRAC", "Cisco Specific", "Aruba/HP", "Fortinet", "Palo Alto", "APC"}...)
	}

	a.oidCategorySelect = widget.NewSelect(categories, nil)

	a.oidSelect = widget.NewSelect([]string{}, a.onOIDSelected)
	a.customOIDEntry = widget.NewEntry()

	// Fingerprinting
	vendorOptions := []string{"auto-detect"}
	vendorOptions = append(vendorOptions, fingerprint.GetSupportedVendors()...)
	vendorOptions = append(vendorOptions, "generic")
	a.fingerprintVendorSelect = widget.NewSelect(vendorOptions, nil)
	a.fingerprintVendorSelect.SetSelected("auto-detect")

	// Results
	a.resultsText = widget.NewRichText()
	a.resultsText.Wrapping = fyne.TextWrapWord

	// Initialize result messages slice
	a.resultMessages = []string{}

	// Set up OID category callback and initialize
	a.oidCategorySelect.OnChanged = a.onOIDCategoryChange
	a.onOIDCategoryChange("Common MIB-II")
	a.oidCategorySelect.SetSelected("Common MIB-II")

	// Load saved settings AFTER widgets are created
	a.loadSettings()

	// Set up auto-save on changes
	a.setupAutoSave()
}

func (a *SNMPTestApp) makeConnectionTab() *container.Scroll {
	// Basic settings form
	basicForm := &widget.Form{
		Items: []*widget.FormItem{
			{Text: "Target IP", Widget: a.ipEntry},
			{Text: "Port", Widget: a.portEntry},
			{Text: "Timeout", Widget: a.timeoutEntry},
			{Text: "Retries", Widget: a.retriesEntry},
		},
	}

	// Version selection
	versionCard := widget.NewCard("SNMP Version", "", a.versionRadio)

	// SNMPv2c settings
	v2cForm := &widget.Form{
		Items: []*widget.FormItem{
			{Text: "Community", Widget: a.communityEntry},
		},
	}
	a.v2cCard = widget.NewCard("SNMPv2c Settings", "", v2cForm)

	// SNMPv3 settings
	v3Form := &widget.Form{
		Items: []*widget.FormItem{
			{Text: "Username", Widget: a.usernameEntry},
			{Text: "Auth Protocol", Widget: a.authProtocolSelect},
			{Text: "Auth Key", Widget: a.authKeyEntry},
			{Text: "Priv Protocol", Widget: a.privProtocolSelect},
			{Text: "Priv Key", Widget: a.privKeyEntry},
		},
	}
	a.v3Card = widget.NewCard("SNMPv3 Settings", "", v3Form)

	// Test connection button
	testBtn := widget.NewButton("Test Connection", a.testConnection)
	testBtn.Importance = widget.HighImportance

	content := container.NewVBox(
		widget.NewCard("Basic Settings", "", basicForm),
		versionCard,
		a.v2cCard,
		a.v3Card,
		container.NewCenter(testBtn),
	)

	// Set the version selection after cards are created
	a.versionRadio.SetSelected("SNMPv3")

	return container.NewScroll(content)
}

func (a *SNMPTestApp) makeOperationsTab() *fyne.Container {
	// Operation selection
	operationCard := widget.NewCard("SNMP Operation", "", a.operationRadio)

	// OID selection form
	oidForm := &widget.Form{
		Items: []*widget.FormItem{
			{Text: "Category", Widget: a.oidCategorySelect},
			{Text: "Common OIDs", Widget: a.oidSelect},
			{Text: "Custom OID", Widget: a.customOIDEntry},
		},
	}
	oidCard := widget.NewCard("OID Selection", "", oidForm)

	// Action buttons
	executeBtn := widget.NewButton("Execute SNMP Operation", a.executeSNMPOperation)
	executeBtn.Importance = widget.HighImportance

	clearBtn := widget.NewButton("Clear Results", a.clearResults)

	testAllBtn := widget.NewButton("Test All Common OIDs", a.testAllCommonOIDs)

	buttonContainer := container.NewHBox(
		executeBtn,
		clearBtn,
		testAllBtn,
	)

	return container.NewVBox(
		operationCard,
		oidCard,
		buttonContainer,
	)
}

func (a *SNMPTestApp) makeFingerprintingTab() *fyne.Container {
	// Vendor selection
	vendorForm := &widget.Form{
		Items: []*widget.FormItem{
			{Text: "Target Vendor", Widget: a.fingerprintVendorSelect},
		},
	}
	vendorCard := widget.NewCard("Vendor Selection", "", vendorForm)

	// Main fingerprinting buttons
	quickDetectionBtn := widget.NewButton("Quick Vendor Detection", a.quickVendorDetection)
	quickDetectionBtn.Importance = widget.MediumImportance

	fullFingerprintBtn := widget.NewButton("Full Vendor Fingerprint (Serial)", a.fullVendorFingerprint)
	fullFingerprintBtn.Importance = widget.HighImportance

	testAllVendorsBtn := widget.NewButton("Test All Vendors (Serial)", a.testAllVendors)

	mainButtons := container.NewVBox(
		quickDetectionBtn,
		fullFingerprintBtn,
		testAllVendorsBtn,
	)

	// Dynamic vendor-specific buttons
	vendorButtons := container.NewVBox()

	// Create buttons for each configured vendor
	if fingerprint.GlobalConfigManager != nil && fingerprint.GlobalConfigManager.GetConfig() != nil {
		config := fingerprint.GlobalConfigManager.GetConfig()
		for vendorKey, vendorConfig := range config.Vendors {
			// Capture vendorKey in closure
			currentVendor := vendorKey
			displayName := vendorConfig.DisplayName

			btn := widget.NewButton(fmt.Sprintf("%s Fingerprint", displayName), func() {
				a.performVendorFingerprint(currentVendor)
			})
			vendorButtons.Add(btn)
		}
	} else {
		// Fallback buttons if YAML not loaded
		fallbackVendors := []struct{ key, name string }{
			{"dell", "Dell iDRAC"},
			{"cisco", "Cisco"},
			{"aruba", "Aruba/HP"},
			{"fortinet", "Fortinet"},
			{"palo_alto", "Palo Alto"},
			{"apc", "APC"},
		}

		for _, v := range fallbackVendors {
			currentVendor := v.key
			btn := widget.NewButton(fmt.Sprintf("%s Fingerprint", v.name), func() {
				a.performVendorFingerprint(currentVendor)
			})
			vendorButtons.Add(btn)
		}
	}

	return container.NewVBox(
		vendorCard,
		widget.NewCard("General Operations", "", mainButtons),
		widget.NewCard("Vendor-Specific Operations", "", vendorButtons),
	)
}

func (a *SNMPTestApp) makeResultsTab() *container.Scroll {
	return container.NewScroll(a.resultsText)
}

// Event handlers
func (a *SNMPTestApp) onVersionChange(value string) {
	if a.v2cCard == nil || a.v3Card == nil {
		return
	}

	if value == "SNMPv2c" {
		a.v2cCard.Show()
		a.v3Card.Hide()
	} else {
		a.v2cCard.Hide()
		a.v3Card.Show()
	}
}

func (a *SNMPTestApp) onOIDCategoryChange(value string) {
	if a.oidSelect == nil {
		return
	}

	var oidMap map[string]string

	if value == "Common MIB-II" {
		oidMap = fingerprint.CommonOIDs
	} else {
		// Find vendor by display name
		oidMap = a.getVendorOIDsByDisplayName(value)
	}

	options := make([]string, 0, len(oidMap))
	for name := range oidMap {
		options = append(options, name)
	}

	a.oidSelect.Options = options
	a.oidSelect.Refresh()
}

func (a *SNMPTestApp) onOIDSelected(value string) {
	// Get all OIDs from all sources
	allOIDs := make(map[string]string)

	// Add common OIDs
	for k, v := range fingerprint.CommonOIDs {
		allOIDs[k] = v
	}

	// Add all vendor OIDs
	for _, vendorConfig := range fingerprint.VendorFingerprints {
		for _, oid := range vendorConfig.FingerprintOIDs {
			allOIDs[oid.Name] = oid.OID
		}
	}

	if oid, exists := allOIDs[value]; exists {
		a.customOIDEntry.SetText(oid)
	}
}

// Helper function to get vendor OIDs by display name
func (a *SNMPTestApp) getVendorOIDsByDisplayName(displayName string) map[string]string {
	oidMap := make(map[string]string)

	// First try to find by display name from YAML config
	if fingerprint.GlobalConfigManager != nil && fingerprint.GlobalConfigManager.GetConfig() != nil {
		config := fingerprint.GlobalConfigManager.GetConfig()
		for vendorKey, vendorConfig := range config.Vendors {
			if vendorConfig.DisplayName == displayName {
				if fpConfig, exists := fingerprint.VendorFingerprints[vendorKey]; exists {
					for _, oid := range fpConfig.FingerprintOIDs {
						oidMap[oid.Name] = oid.OID
					}
				}
				return oidMap
			}
		}
	}

	// Fallback: try to find by vendor key directly
	for vendorKey, vendorConfig := range fingerprint.VendorFingerprints {
		// Simple heuristic: if display name contains vendor key
		if strings.Contains(strings.ToLower(displayName), vendorKey) {
			for _, oid := range vendorConfig.FingerprintOIDs {
				oidMap[oid.Name] = oid.OID
			}
			return oidMap
		}
	}

	return oidMap
}

// Dynamic fingerprinting function
func (a *SNMPTestApp) performVendorFingerprint(vendorKey string) {
	// Get vendor display name
	displayName := vendorKey
	if fingerprint.GlobalConfigManager != nil && fingerprint.GlobalConfigManager.GetConfig() != nil {
		if vendorConfig, exists := fingerprint.GlobalConfigManager.GetConfig().Vendors[vendorKey]; exists {
			displayName = vendorConfig.DisplayName
		}
	}

	a.logMessage(fmt.Sprintf("Performing %s fingerprinting...", displayName), "info")

	// Close existing connection
	a.closeSNMPClient()

	// Create new client
	err := a.createSNMPClient()
	if err != nil {
		a.logMessage(fmt.Sprintf("Connection failed: %v", err), "error")
		return
	}
	defer a.closeSNMPClient()

	// Get vendor-specific OIDs
	vendorOIDs := fingerprint.GetVendorPriorityOIDs(vendorKey, 10)

	if len(vendorOIDs) == 0 {
		a.logMessage(fmt.Sprintf("No OIDs configured for %s", displayName), "error")
		return
	}

	vendorDetected := false
	vendorInfo := make(map[string]string)

	a.logMessage(fmt.Sprintf("Testing key %s OIDs...", displayName), "info")

	for _, oidEntry := range vendorOIDs {
		value, err := a.snmpClient.Get(oidEntry.OID)
		if err != nil {
			a.logMessage(fmt.Sprintf("FAIL %s (%s): %v", oidEntry.Name, oidEntry.OID, err), "error")
		} else if fingerprint.IsValidSNMPValue(value) {
			a.logMessage(fmt.Sprintf("CHECK %s: %s", oidEntry.Name, value), "success")
			vendorDetected = true
			vendorInfo[oidEntry.Name] = value
		} else {
			a.logMessage(fmt.Sprintf("FAIL %s (%s): No valid data", oidEntry.Name, oidEntry.OID), "error")
		}
	}

	// Summary
	a.logMessage("", "info") // Empty line
	if vendorDetected {
		a.logMessage(fmt.Sprintf("%s DETECTED! This appears to be a %s device.", strings.ToUpper(displayName), displayName), "success")

		// Show key information based on common field patterns
		keyFields := [][]string{
			{"model", "Model"},
			{"service tag", "Service Tag"},
			{"serial", "Serial Number"},
			{"version", "Version"},
			{"status", "Status"},
		}

		for _, fieldPattern := range keyFields {
			pattern, label := fieldPattern[0], fieldPattern[1]
			for fieldName, value := range vendorInfo {
				if strings.Contains(strings.ToLower(fieldName), pattern) {
					a.logMessage(fmt.Sprintf("   %s: %s", label, value), "info")
					break
				}
			}
		}
	} else {
		a.logMessage(fmt.Sprintf("No %s detected. This may not be a %s device or SNMP is not configured properly.", displayName, displayName), "error")
	}
}

// SNMP client management
func (a *SNMPTestApp) createSNMPClient() error {
	// Parse port
	port, err := strconv.ParseUint(a.portEntry.Text, 10, 16)
	if err != nil {
		return fmt.Errorf("invalid port: %w", err)
	}

	// Parse timeout
	timeout, err := snmp.ParseTimeout(a.timeoutEntry.Text)
	if err != nil {
		return fmt.Errorf("invalid timeout: %w", err)
	}

	// Parse retries
	retries, err := strconv.Atoi(a.retriesEntry.Text)
	if err != nil {
		return fmt.Errorf("invalid retries: %w", err)
	}

	// Create client based on version
	if a.versionRadio.Selected == "SNMPv2c" {
		a.snmpClient = snmp.NewClient(a.ipEntry.Text, uint16(port))
		a.snmpClient.Community = a.communityEntry.Text
		a.snmpClient.Version = 1 // SNMPv2c
	} else {
		// SNMPv3
		a.snmpClient = snmp.NewSNMPv3Client(
			a.ipEntry.Text,
			uint16(port),
			a.usernameEntry.Text,
			a.authKeyEntry.Text,
			a.privKeyEntry.Text,
		)

		// Set auth and priv protocols
		a.snmpClient.AuthProtocol = snmp.AuthProtocolFromString(a.authProtocolSelect.Selected)
		a.snmpClient.PrivProtocol = snmp.PrivProtocolFromString(a.privProtocolSelect.Selected)
	}

	a.snmpClient.Timeout = timeout
	a.snmpClient.Retries = retries

	// Connect
	return a.snmpClient.Connect()
}

func (a *SNMPTestApp) closeSNMPClient() {
	if a.snmpClient != nil {
		a.snmpClient.Close()
		a.snmpClient = nil
	}
}

// Action handlers
func (a *SNMPTestApp) testConnection() {
	a.logMessage("Testing connection...", "info")

	// Close existing connection
	a.closeSNMPClient()

	// Create new client
	err := a.createSNMPClient()
	if err != nil {
		a.logMessage(fmt.Sprintf("Connection failed: %v", err), "error")
		return
	}
	defer a.closeSNMPClient()

	// Test connection
	sysDescr, err := a.snmpClient.TestConnection()
	if err != nil {
		a.logMessage(fmt.Sprintf("Connection test failed: %v", err), "error")
		return
	}

	a.logMessage("Connection test SUCCESSFUL!", "success")
	a.logMessage(fmt.Sprintf("Device description: %s", sysDescr), "info")
}

func (a *SNMPTestApp) executeSNMPOperation() {
	a.logMessage("Executing SNMP operation...", "info")

	oid := strings.TrimSpace(a.customOIDEntry.Text)
	if oid == "" {
		a.logMessage("Error: OID is required", "error")
		return
	}

	operation := a.operationRadio.Selected
	a.logMessage(fmt.Sprintf("Operation: %s, OID: %s", operation, oid), "info")

	// Close existing connection
	a.closeSNMPClient()

	// Create new client
	err := a.createSNMPClient()
	if err != nil {
		a.logMessage(fmt.Sprintf("Connection failed: %v", err), "error")
		return
	}
	defer a.closeSNMPClient()

	// Execute operation
	switch operation {
	case "GET":
		value, err := a.snmpClient.Get(oid)
		if err != nil {
			a.logMessage(fmt.Sprintf("GET failed: %v", err), "error")
		} else {
			a.logMessage(fmt.Sprintf("SUCCESS: %s = %s", oid, value), "success")
		}

	case "GETNEXT":
		nextOID, value, err := a.snmpClient.GetNext(oid)
		if err != nil {
			a.logMessage(fmt.Sprintf("GETNEXT failed: %v", err), "error")
		} else {
			a.logMessage(fmt.Sprintf("SUCCESS: %s = %s", nextOID, value), "success")
		}

	case "WALK":
		variables, err := a.snmpClient.Walk(oid)
		if err != nil {
			a.logMessage(fmt.Sprintf("WALK failed: %v", err), "error")
		} else {
			a.logMessage(fmt.Sprintf("WALK SUCCESS: Found %d variables", len(variables)), "success")
			for i, variable := range variables {
				if i >= 20 { // Limit output to first 20 items
					a.logMessage(fmt.Sprintf("... and %d more items", len(variables)-20), "info")
					break
				}
				a.logMessage(fmt.Sprintf("  %s = %s", variable.OID, variable.Value), "info")
			}
		}

	case "GETBULK":
		variables, err := a.snmpClient.GetBulk(oid, 0, 10)
		if err != nil {
			a.logMessage(fmt.Sprintf("GETBULK failed: %v", err), "error")
		} else {
			a.logMessage(fmt.Sprintf("GETBULK SUCCESS: Found %d variables", len(variables)), "success")
			for _, variable := range variables {
				a.logMessage(fmt.Sprintf("  %s = %s", variable.OID, variable.Value), "info")
			}
		}
	}
}

func (a *SNMPTestApp) testAllCommonOIDs() {
	a.logMessage("Testing all common OIDs...", "info")

	// Close existing connection
	a.closeSNMPClient()

	// Create new client
	err := a.createSNMPClient()
	if err != nil {
		a.logMessage(fmt.Sprintf("Connection failed: %v", err), "error")
		return
	}
	defer a.closeSNMPClient()

	// Test each common OID
	for name, oid := range fingerprint.CommonOIDs {
		value, err := a.snmpClient.Get(oid)
		if err != nil {
			a.logMessage(fmt.Sprintf("FAIL %s (%s): %v", name, oid, err), "error")
		} else {
			a.logMessage(fmt.Sprintf("CHECK %s: %s", name, value), "success")
		}
	}

	a.logMessage("All common OIDs test complete", "info")
}

func (a *SNMPTestApp) quickVendorDetection() {
	a.logMessage("Performing quick vendor detection...", "info")

	// Close existing connection
	a.closeSNMPClient()

	// Create new client
	err := a.createSNMPClient()
	if err != nil {
		a.logMessage(fmt.Sprintf("Connection failed: %v", err), "error")
		return
	}
	defer a.closeSNMPClient()

	// Create fingerprinting client
	fpClient := fingerprint.NewClient(a.snmpClient)
	fpClient.SetLogger(func(msg string) {
		a.logMessage(msg, "info")
	})

	// Perform quick detection
	result, err := fpClient.QuickVendorDetection()
	if err != nil {
		a.logMessage(fmt.Sprintf("Quick detection failed: %v", err), "error")
		return
	}

	// Display results
	a.logMessage("=== QUICK VENDOR DETECTION RESULTS ===", "header")
	a.logMessage(fmt.Sprintf("Detected Vendor: %s", result.DetectedVendor), "success")
	a.logMessage(fmt.Sprintf("Confidence: %s", result.Confidence), "info")
	a.logMessage(fmt.Sprintf("Detection Method: %s", result.DetectionMethod), "info")
	a.logMessage(fmt.Sprintf("Scan Duration: %v", result.ScanDuration), "info")

	if len(result.FingerprintData) > 0 {
		a.logMessage("Basic System Information:", "info")
		for field, value := range result.FingerprintData {
			a.logMessage(fmt.Sprintf("  %s: %s", field, value), "info")
		}
	}
}

func (a *SNMPTestApp) fullVendorFingerprint() {
	a.logMessage("Performing full vendor fingerprinting (serial mode)...", "info")
	a.logMessage("Using stable serial querying to avoid device overload.", "info")

	targetVendor := a.fingerprintVendorSelect.Selected
	a.logMessage(fmt.Sprintf("Target vendor: %s", targetVendor), "info")

	// Close existing connection
	a.closeSNMPClient()

	// Create new client
	err := a.createSNMPClient()
	if err != nil {
		a.logMessage(fmt.Sprintf("Connection failed: %v", err), "error")
		return
	}
	defer a.closeSNMPClient()

	// Create fingerprinting client
	fpClient := fingerprint.NewClient(a.snmpClient)
	fpClient.SetLogger(func(msg string) {
		a.logMessage(msg, "info")
	})

	// Perform fingerprinting with serial approach
	ctx := context.Background()
	result, err := fpClient.PerformFingerprinting(ctx, targetVendor)
	if err != nil {
		a.logMessage(fmt.Sprintf("Fingerprinting failed: %v", err), "error")
		return
	}

	// Display results
	a.logMessage("=== FULL VENDOR FINGERPRINTING RESULTS ===", "header")
	a.logMessage(fmt.Sprintf("Detected Vendor: %s", result.DetectedVendor), "success")
	a.logMessage(fmt.Sprintf("Confidence: %s", result.Confidence), "info")
	a.logMessage(fmt.Sprintf("Detection Method: %s", result.DetectionMethod), "info")
	a.logMessage(fmt.Sprintf("Scan Duration: %v", result.ScanDuration), "info")
	a.logMessage(fmt.Sprintf("Fields Found: %d", len(result.FingerprintData)), "info")

	if len(result.FingerprintData) > 0 {
		a.logMessage("Vendor-Specific Data:", "info")
		for field, value := range result.FingerprintData {
			// Show important fields in full
			if strings.Contains(strings.ToLower(field), "service tag") ||
				strings.Contains(strings.ToLower(field), "serial") ||
				strings.Contains(strings.ToLower(field), "model") ||
				strings.Contains(strings.ToLower(field), "version") {
				a.logMessage(fmt.Sprintf("  ✅ %s: %s", field, value), "success")
			} else {
				// Truncate less important fields
				displayValue := value
				if len(value) > 80 {
					displayValue = value[:80] + "..."
				}
				a.logMessage(fmt.Sprintf("  ℹ️ %s: %s", field, displayValue), "info")
			}
		}

		// Show summary
		important := fingerprint.ExtractImportantFields(result.FingerprintData)
		if len(important) > 0 {
			a.logMessage("", "info") // Empty line for separation
			a.logMessage("🔑 KEY INFORMATION SUMMARY:", "header")
			for category, value := range important {
				a.logMessage(fmt.Sprintf("  %s: %s", strings.Title(category), value), "success")
			}
		}
	} else {
		a.logMessage("No vendor-specific data found. Device may not support these OIDs or vendor detection was incorrect.", "warning")
	}

	if result.ErrorMessage != "" {
		a.logMessage(fmt.Sprintf("⚠️ Error: %s", result.ErrorMessage), "error")
	}

	a.logMessage("", "info") // Empty line for separation
	a.logMessage("Fingerprinting complete. Serial querying provides stable results.", "info")
}

func (a *SNMPTestApp) testAllVendors() {
	a.logMessage("Testing fingerprinting against all known vendors (serial mode)...", "info")
	a.logMessage("This may take a few minutes as we query each vendor sequentially for stability.", "info")

	// Close existing connection
	a.closeSNMPClient()

	// Create new client
	err := a.createSNMPClient()
	if err != nil {
		a.logMessage(fmt.Sprintf("Connection failed: %v", err), "error")
		return
	}
	defer a.closeSNMPClient()

	// Create fingerprinting client
	fpClient := fingerprint.NewClient(a.snmpClient)
	fpClient.SetLogger(func(msg string) {
		// Only show major progress updates to avoid spam
		if strings.Contains(msg, "Testing") || strings.Contains(msg, "complete") {
			a.logMessage(msg, "info")
		}
	})

	// Test all vendors
	ctx := context.Background()
	results, err := fpClient.TestAllVendors(ctx)
	if err != nil {
		a.logMessage(fmt.Sprintf("Vendor testing failed: %v", err), "error")
		return
	}

	// Display results
	a.logMessage("=== ALL VENDOR TESTING RESULTS ===", "header")

	type vendorResult struct {
		vendor     string
		fieldCount int
		detected   string
		duration   time.Duration
	}

	var bestMatches []vendorResult

	for vendor, result := range results {
		if result.Success && len(result.FingerprintData) > 0 {
			bestMatches = append(bestMatches, vendorResult{
				vendor:     vendor,
				fieldCount: len(result.FingerprintData),
				detected:   result.DetectedVendor,
				duration:   result.ScanDuration,
			})
			a.logMessage(fmt.Sprintf("  ✅ %s: %d fields detected (%v)", vendor, len(result.FingerprintData), result.ScanDuration), "success")
		} else {
			a.logMessage(fmt.Sprintf("  ❌ %s: No data detected", vendor), "error")
		}
	}

	// Show recommendations
	if len(bestMatches) > 0 {
		a.logMessage("", "info") // Empty line
		a.logMessage("🏆 TOP MATCHES BY DATA RICHNESS:", "header")

		// Sort by field count (descending)
		for i := 0; i < len(bestMatches)-1; i++ {
			for j := i + 1; j < len(bestMatches); j++ {
				if bestMatches[i].fieldCount < bestMatches[j].fieldCount {
					bestMatches[i], bestMatches[j] = bestMatches[j], bestMatches[i]
				}
			}
		}

		// Show top 5
		count := len(bestMatches)
		if count > 5 {
			count = 5
		}

		for i := 0; i < count; i++ {
			match := bestMatches[i]
			a.logMessage(fmt.Sprintf("  %d. %s: %d fields (detected as: %s)",
				i+1, match.vendor, match.fieldCount, match.detected), "success")
		}

		// Show recommendation
		top := bestMatches[0]
		a.logMessage("", "info") // Empty line
		if top.vendor == "auto-detect" {
			a.logMessage(fmt.Sprintf("🎯 RECOMMENDATION: Auto-detection works well (detected as %s)", top.detected), "success")
		} else {
			a.logMessage(fmt.Sprintf("🎯 RECOMMENDATION: Use %s fingerprinting (%d fields)", top.vendor, top.fieldCount), "success")
		}
	} else {
		a.logMessage("❌ No successful fingerprinting detected for any vendor", "error")
		a.logMessage("This device may not support SNMP properly or may require different credentials.", "warning")
	}
}

func (a *SNMPTestApp) dellIdracFingerprint() {
	a.performVendorFingerprint("dell")
}

func (a *SNMPTestApp) clearResults() {
	a.resultMessages = []string{}
	a.resultsText.ParseMarkdown("")
	a.resultsText.Refresh()
}

// Logging function
func (a *SNMPTestApp) logMessage(message, level string) {
	var prefix string
	switch level {
	case "error":
		prefix = "❌ **ERROR**: "
	case "success":
		prefix = "✅ **SUCCESS**: "
	case "warning":
		prefix = "⚠️ **WARNING**: "
	case "info":
		prefix = "ℹ️ **INFO**: "
	case "header":
		prefix = "🔍 **"
		message = message + "**"
	default:
		prefix = ""
	}

	// Add to our message slice
	a.resultMessages = append(a.resultMessages, prefix+message)

	// Keep only last 100 messages to prevent memory issues
	if len(a.resultMessages) > 100 {
		a.resultMessages = a.resultMessages[1:]
	}

	// Rebuild the content as markdown
	content := ""
	for _, msg := range a.resultMessages {
		content += msg + "\n\n"
	}

	a.resultsText.ParseMarkdown(content)
	a.resultsText.Refresh()
}

// Settings keys - define as constants for consistency
const (
	PrefKeyIP           = "connection.ip"
	PrefKeyPort         = "connection.port"
	PrefKeyTimeout      = "connection.timeout"
	PrefKeyRetries      = "connection.retries"
	PrefKeyVersion      = "connection.version"
	PrefKeyCommunity    = "connection.community"
	PrefKeyUsername     = "connection.username"
	PrefKeyAuthProtocol = "connection.auth_protocol"
	PrefKeyAuthKey      = "connection.auth_key"
	PrefKeyPrivProtocol = "connection.priv_protocol"
	PrefKeyPrivKey      = "connection.priv_key"
)

func (a *SNMPTestApp) loadSettings() {
	a.loadSettingsWithDefaults()
}

// saveSettings saves current settings to preferences
func (a *SNMPTestApp) saveSettings() {
	prefs := a.app.Preferences()

	// Save basic connection settings
	prefs.SetString(PrefKeyIP, a.ipEntry.Text)
	prefs.SetString(PrefKeyPort, a.portEntry.Text)
	prefs.SetString(PrefKeyTimeout, a.timeoutEntry.Text)
	prefs.SetString(PrefKeyRetries, a.retriesEntry.Text)

	// Save SNMP version
	prefs.SetString(PrefKeyVersion, a.versionRadio.Selected)

	// Save SNMPv2c settings
	prefs.SetString(PrefKeyCommunity, a.communityEntry.Text)

	// Save SNMPv3 settings
	prefs.SetString(PrefKeyUsername, a.usernameEntry.Text)
	prefs.SetString(PrefKeyAuthProtocol, a.authProtocolSelect.Selected)
	prefs.SetString(PrefKeyAuthKey, a.authKeyEntry.Text)
	prefs.SetString(PrefKeyPrivProtocol, a.privProtocolSelect.Selected)
	prefs.SetString(PrefKeyPrivKey, a.privKeyEntry.Text)
}

// setupAutoSave sets up automatic saving when fields change
func (a *SNMPTestApp) setupAutoSave() {
	// Save settings when connection fields change
	a.ipEntry.OnChanged = func(string) { a.saveSettings() }
	a.portEntry.OnChanged = func(string) { a.saveSettings() }
	a.timeoutEntry.OnChanged = func(string) { a.saveSettings() }
	a.retriesEntry.OnChanged = func(string) { a.saveSettings() }
	a.communityEntry.OnChanged = func(string) { a.saveSettings() }
	a.usernameEntry.OnChanged = func(string) { a.saveSettings() }
	a.authKeyEntry.OnChanged = func(string) { a.saveSettings() }
	a.privKeyEntry.OnChanged = func(string) { a.saveSettings() }

	// Save settings when dropdowns change
	originalAuthCallback := a.authProtocolSelect.OnChanged
	a.authProtocolSelect.OnChanged = func(s string) {
		if originalAuthCallback != nil {
			originalAuthCallback(s)
		}
		a.saveSettings()
	}

	originalPrivCallback := a.privProtocolSelect.OnChanged
	a.privProtocolSelect.OnChanged = func(s string) {
		if originalPrivCallback != nil {
			originalPrivCallback(s)
		}
		a.saveSettings()
	}

	// Save settings when version changes
	originalVersionCallback := a.versionRadio.OnChanged
	a.versionRadio.OnChanged = func(s string) {
		if originalVersionCallback != nil {
			originalVersionCallback(s)
		}
		a.saveSettings()
	}
}
