package main

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// CyberpunkTheme implements the same polished theme from your network scanner
type CyberpunkTheme struct{}

// Color returns colors for the cyberpunk theme - matching your network scanner exactly
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

// Apply the enhanced theme to your SNMP toolkit
func applyCyberpunkTheme(app fyne.App) {
	cyberpunkTheme := &CyberpunkTheme{}
	app.Settings().SetTheme(cyberpunkTheme)
}

// Enhanced tab implementations using regular widget.Card (no struct changes needed)

// Keep your existing makeConnectionTab but with better card titles
func (a *SNMPTestApp) makeConnectionTabEnhanced() *container.Scroll {
	// Basic settings form
	basicForm := &widget.Form{
		Items: []*widget.FormItem{
			{Text: "Target IP", Widget: a.ipEntry},
			{Text: "Port", Widget: a.portEntry},
			{Text: "Timeout", Widget: a.timeoutEntry},
			{Text: "Retries", Widget: a.retriesEntry},
		},
	}

	// Version selection with better styling
	versionCard := widget.NewCard("SNMP Protocol Version", "Select authentication method", a.versionRadio)

	// SNMPv2c settings
	v2cForm := &widget.Form{
		Items: []*widget.FormItem{
			{Text: "Community", Widget: a.communityEntry},
		},
	}
	a.v2cCard = widget.NewCard("SNMPv2c Configuration", "Community-based authentication", v2cForm)

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
	a.v3Card = widget.NewCard("SNMPv3 Configuration", "Secure authentication and encryption", v3Form)

	// Test connection button with cyberpunk styling
	testBtn := widget.NewButton("🔍 Test Connection", a.testConnection)
	testBtn.Importance = widget.HighImportance

	// Enhanced basic settings card
	basicCard := widget.NewCard("Network Connection", "Target device parameters", basicForm)

	content := container.NewVBox(
		basicCard,
		versionCard,
		a.v2cCard,
		a.v3Card,
		container.NewCenter(testBtn),
	)

	// Set the version selection after cards are created
	a.versionRadio.SetSelected("SNMPv3")

	return container.NewScroll(content)
}

// Enhanced operations tab with better card styling
func (a *SNMPTestApp) makeOperationsTabEnhanced() *fyne.Container {
	// Operation selection
	operationCard := widget.NewCard("SNMP Operations", "Choose query type", a.operationRadio)

	// OID selection form
	oidForm := &widget.Form{
		Items: []*widget.FormItem{
			{Text: "Category", Widget: a.oidCategorySelect},
			{Text: "Common OIDs", Widget: a.oidSelect},
			{Text: "Custom OID", Widget: a.customOIDEntry},
		},
	}
	oidCard := widget.NewCard("Object Identifier (OID)", "Select or enter target OID", oidForm)

	// Action buttons with better styling
	executeBtn := widget.NewButton("⚡ Execute SNMP Operation", a.executeSNMPOperation)
	executeBtn.Importance = widget.HighImportance

	clearBtn := widget.NewButton("🗑️ Clear Results", a.clearResults)

	testAllBtn := widget.NewButton("🔍 Test All Common OIDs", a.testAllCommonOIDs)

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

// Enhanced fingerprinting tab
func (a *SNMPTestApp) makeFingerprintingTabEnhanced() *fyne.Container {
	// Vendor selection
	vendorForm := &widget.Form{
		Items: []*widget.FormItem{
			{Text: "Target Vendor", Widget: a.fingerprintVendorSelect},
		},
	}
	vendorCard := widget.NewCard("Vendor Detection", "Select target vendor or auto-detect", vendorForm)

	// Fingerprinting buttons with enhanced styling
	quickDetectionBtn := widget.NewButton("⚡ Quick Vendor Detection", a.quickVendorDetection)
	quickDetectionBtn.Importance = widget.MediumImportance

	fullFingerprintBtn := widget.NewButton("🔍 Full Vendor Fingerprint", a.fullVendorFingerprint)
	fullFingerprintBtn.Importance = widget.HighImportance

	testAllVendorsBtn := widget.NewButton("🌐 Test All Vendors", a.testAllVendors)

	dellFingerprintBtn := widget.NewButton("🖥️ Dell iDRAC Fingerprint", a.dellIdracFingerprint)

	buttonContainer := container.NewVBox(
		quickDetectionBtn,
		fullFingerprintBtn,
		testAllVendorsBtn,
		dellFingerprintBtn,
	)

	operationsCard := widget.NewCard("Fingerprinting Operations", "Advanced device identification", buttonContainer)

	return container.NewVBox(
		vendorCard,
		operationsCard,
	)
}
