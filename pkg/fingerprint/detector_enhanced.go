// detector_enhanced.go
package fingerprint

import (
	"fmt"
	"strings"
	"time"
)

// VendorValidator represents a vendor-specific validation rule
type VendorValidator struct {
	Vendor           string         `json:"vendor"`
	Priority         int            `json:"priority"`          // Lower = higher priority
	ValidatorOIDs    []ValidatorOID `json:"validator_oids"`    // OIDs that definitively identify this vendor
	ExclusionOIDs    []ValidatorOID `json:"exclusion_oids"`    // OIDs that exclude this vendor
	RequiredPatterns []string       `json:"required_patterns"` // Required patterns in sysDescr
	ExclusionPatterns []string      `json:"exclusion_patterns"`// Patterns that exclude this vendor
	MinConfidence    int            `json:"min_confidence"`    // Minimum confidence score needed
	FallbackPatterns []string       `json:"fallback_patterns"` // Fallback string patterns
}

// ValidatorOID represents an OID used for vendor validation
type ValidatorOID struct {
	OID             string   `json:"oid"`
	ExpectedValues  []string `json:"expected_values,omitempty"`  // Expected return values (empty = any non-error)
	ExpectedPattern string   `json:"expected_pattern,omitempty"` // Regex pattern for value
	Description     string   `json:"description"`
	Weight          int      `json:"weight"`          // Confidence weight (1-100)
	IsDefinitive    bool     `json:"is_definitive"`   // If true, this OID alone confirms vendor
	MustRespond     bool     `json:"must_respond"`    // If true, OID must respond (not timeout/error)
}

// VendorScore tracks scoring for a vendor during detection
type VendorScore struct {
	Vendor           string
	BaseScore        int
	OIDScore         int
	PatternScore     int
	ExclusionPenalty int
	FinalScore       int
	TotalTests       int
	PassedTests      int
	ValidatedOIDs    []string
	FailedOIDs       []string
	RawData          map[string]string
}

// Global validator registry - can be populated from YAML or hardcoded
var GlobalValidators []VendorValidator

// Initialize validators on package load
func init() {
	GlobalValidators = getBuiltInValidators()
}

// DetectVendorAdvanced performs sophisticated vendor detection using OID validation
// This replaces the existing DetectVendorComprehensive function
func DetectVendorAdvanced(sysDescr, sysContact, sysName, sysLocation string, snmpClient SNMPClient) (vendor, confidence, method string) {
	startTime := time.Now()
	
	// Create basic info map
	basicInfo := map[string]string{
		"sysDescr":    sysDescr,
		"sysContact":  sysContact,
		"sysName":     sysName,
		"sysLocation": sysLocation,
	}
	
	// First, try definitive OID validation for quick identification
	if vendor, conf := detectByDefinitiveOIDs(basicInfo, snmpClient); vendor != "unknown" {
		return vendor, fmt.Sprintf("%d", conf), "definitive_oid"
	}
	
	// If no definitive match, run comprehensive validation
	result := detectByComprehensiveValidation(basicInfo, snmpClient)
	
	// Convert numeric confidence to string
	confidenceStr := "none"
	if result.confidence >= 80 {
		confidenceStr = "high"
	} else if result.confidence >= 50 {
		confidenceStr = "medium"
	} else if result.confidence >= 20 {
		confidenceStr = "low"
	}
	
	fmt.Printf("Advanced detection completed in %v: %s (confidence: %s)\n", 
		time.Since(startTime), result.vendor, confidenceStr)
	
	return result.vendor, confidenceStr, result.method
}

// detectByDefinitiveOIDs tests only the most definitive OIDs first for quick identification
func detectByDefinitiveOIDs(basicInfo map[string]string, snmpClient SNMPClient) (string, int) {
	if snmpClient == nil {
		return "unknown", 0
	}
	
	// Test definitive OIDs for each vendor in priority order
	for _, validator := range getSortedValidators() {
		for _, validatorOID := range validator.ValidatorOIDs {
			if !validatorOID.IsDefinitive {
				continue
			}
			
			fmt.Printf("Testing definitive OID for %s: %s\n", validator.Vendor, validatorOID.OID)
			
			value, err := snmpClient.Get(validatorOID.OID)
			if err != nil {
				fmt.Printf("  FAILED: %v\n", err)
				continue
			}
			
			fmt.Printf("  SUCCESS: %s\n", value)
			
			// Check if value matches expectations
			if validateOIDResponse(validatorOID, value) {
				fmt.Printf("  DEFINITIVE MATCH: %s\n", validator.Vendor)
				return validator.Vendor, 95
			}
		}
	}
	
	return "unknown", 0
}

// detectByComprehensiveValidation performs thorough validation when definitive detection fails
func detectByComprehensiveValidation(basicInfo map[string]string, snmpClient SNMPClient) struct {
	vendor     string
	confidence int
	method     string
} {
	fmt.Printf("Running comprehensive vendor validation...\n")
	
	vendorScores := make(map[string]*VendorScore)
	
	// Initialize vendor scores
	for _, validator := range GlobalValidators {
		vendorScores[validator.Vendor] = &VendorScore{
			Vendor:           validator.Vendor,
			BaseScore:        0,
			OIDScore:         0,
			PatternScore:     0,
			ExclusionPenalty: 0,
			ValidatedOIDs:    []string{},
			FailedOIDs:       []string{},
			RawData:          make(map[string]string),
		}
	}
	
	// Test all validator OIDs (only if SNMP client available)
	if snmpClient != nil {
		testValidatorOIDs(vendorScores, snmpClient)
	}
	
	// Apply pattern matching
	applyPatternScoring(vendorScores, basicInfo)
	
	// Calculate final scores and find best match
	return calculateFinalResult(vendorScores)
}

// testValidatorOIDs tests all validator OIDs and updates scores
func testValidatorOIDs(vendorScores map[string]*VendorScore, snmpClient SNMPClient) {
	for _, validator := range GlobalValidators {
		score := vendorScores[validator.Vendor]
		
		for _, validatorOID := range validator.ValidatorOIDs {
			fmt.Printf("Testing %s OID: %s\n", validator.Vendor, validatorOID.OID)
			
			value, err := snmpClient.Get(validatorOID.OID)
			score.TotalTests++
			
			if err != nil {
				score.FailedOIDs = append(score.FailedOIDs, validatorOID.OID)
				fmt.Printf("  FAILED: %v\n", err)
				
				// Penalty for required OIDs that fail
				if validatorOID.MustRespond {
					score.ExclusionPenalty += 20
				}
				continue
			}
			
			score.ValidatedOIDs = append(score.ValidatedOIDs, validatorOID.OID)
			score.RawData[validatorOID.OID] = value
			
			// Validate response
			if validateOIDResponse(validatorOID, value) {
				score.OIDScore += validatorOID.Weight
				score.PassedTests++
				fmt.Printf("  VALID: %s (weight: %d)\n", value, validatorOID.Weight)
			} else {
				fmt.Printf("  INVALID: %s\n", value)
			}
		}
		
		// Test exclusion OIDs
		for _, exclusionOID := range validator.ExclusionOIDs {
			value, err := snmpClient.Get(exclusionOID.OID)
			if err == nil && validateOIDResponse(exclusionOID, value) {
				score.ExclusionPenalty += exclusionOID.Weight
				fmt.Printf("Exclusion OID matched for %s: %s\n", validator.Vendor, exclusionOID.OID)
			}
		}
	}
}

// applyPatternScoring applies string pattern matching scoring
func applyPatternScoring(vendorScores map[string]*VendorScore, basicInfo map[string]string) {
	sysDescr := strings.ToLower(basicInfo["sysDescr"])
	sysContact := strings.ToLower(basicInfo["sysContact"])
	sysName := strings.ToLower(basicInfo["sysName"])
	
	for _, validator := range GlobalValidators {
		score := vendorScores[validator.Vendor]
		
		// Check required patterns
		requiredMatched := true
		for _, pattern := range validator.RequiredPatterns {
			if !strings.Contains(sysDescr, strings.ToLower(pattern)) {
				requiredMatched = false
				break
			}
		}
		
		if requiredMatched && len(validator.RequiredPatterns) > 0 {
			score.PatternScore += 30
		}
		
		// Check exclusion patterns
		for _, pattern := range validator.ExclusionPatterns {
			if strings.Contains(sysDescr, strings.ToLower(pattern)) ||
			   strings.Contains(sysContact, strings.ToLower(pattern)) ||
			   strings.Contains(sysName, strings.ToLower(pattern)) {
				score.ExclusionPenalty += 50
				fmt.Printf("Exclusion pattern matched for %s: %s\n", validator.Vendor, pattern)
			}
		}
		
		// Check fallback patterns
		for _, pattern := range validator.FallbackPatterns {
			if strings.Contains(sysDescr, strings.ToLower(pattern)) {
				score.PatternScore += 10
			}
		}
	}
}

// calculateFinalResult calculates final scores and returns the best match
func calculateFinalResult(vendorScores map[string]*VendorScore) struct {
	vendor     string
	confidence int
	method     string
} {
	var bestVendor string
	var bestScore int
	
	// Calculate final scores
	for vendor, score := range vendorScores {
		finalScore := score.OIDScore + score.PatternScore - score.ExclusionPenalty
		
		// Apply validator minimum confidence
		validator := getValidator(vendor)
		if validator != nil && finalScore < validator.MinConfidence {
			finalScore = 0
		}
		
		score.FinalScore = finalScore
		
		fmt.Printf("Final score for %s: %d (OID: %d, Pattern: %d, Exclusion: -%d)\n", 
			vendor, finalScore, score.OIDScore, score.PatternScore, score.ExclusionPenalty)
		
		if finalScore > bestScore {
			bestScore = finalScore
			bestVendor = vendor
		}
	}
	
	// Determine confidence level and method
	confidence := 0
	method := "unknown"
	
	if bestScore >= 80 {
		confidence = 90
		method = "high_confidence_oid"
	} else if bestScore >= 50 {
		confidence = 70
		method = "medium_confidence_oid"
	} else if bestScore >= 20 {
		confidence = 40
		method = "low_confidence_pattern"
	}
	
	if bestVendor == "" {
		bestVendor = "unknown"
		confidence = 0
		method = "no_detection"
	}
	
	return struct {
		vendor     string
		confidence int
		method     string
	}{bestVendor, confidence, method}
}

// validateOIDResponse validates if an OID response matches expectations
func validateOIDResponse(validatorOID ValidatorOID, value string) bool {
	// Check for SNMP error responses
	errorResponses := []string{
		"No Such Object currently exists at this OID",
		"No Such Instance currently exists at this OID",
		"End of MIB",
		"NULL",
		"None",
	}
	
	for _, errorResp := range errorResponses {
		if strings.Contains(value, errorResp) {
			return false
		}
	}
	
	// If no expected values specified, any non-error response is valid
	if len(validatorOID.ExpectedValues) == 0 && validatorOID.ExpectedPattern == "" {
		return value != ""
	}
	
	// Check expected values
	for _, expectedValue := range validatorOID.ExpectedValues {
		if strings.Contains(strings.ToLower(value), strings.ToLower(expectedValue)) {
			return true
		}
	}
	
	return false
}

// Helper functions

func getSortedValidators() []VendorValidator {
	// Return validators sorted by priority (lower number = higher priority)
	validators := make([]VendorValidator, len(GlobalValidators))
	copy(validators, GlobalValidators)
	
	// Simple sort by priority
	for i := 0; i < len(validators)-1; i++ {
		for j := i + 1; j < len(validators); j++ {
			if validators[i].Priority > validators[j].Priority {
				validators[i], validators[j] = validators[j], validators[i]
			}
		}
	}
	
	return validators
}

func getValidator(vendor string) *VendorValidator {
	for _, validator := range GlobalValidators {
		if validator.Vendor == vendor {
			return &validator
		}
	}
	return nil
}

// getBuiltInValidators returns the predefined vendor validators
func getBuiltInValidators() []VendorValidator {
	return []VendorValidator{
		{
			Vendor:   "cisco",
			Priority: 10,
			ValidatorOIDs: []ValidatorOID{
				{
					OID:          "1.3.6.1.4.1.9.1.2694",
					Description:  "Cisco Catalyst Model",
					Weight:       80,
					IsDefinitive: true,
					MustRespond:  false,
				},
				{
					OID:          "1.3.6.1.4.1.9.1.2137", 
					Description:  "Cisco Catalyst Old Model",
					Weight:       80,
					IsDefinitive: true,
					MustRespond:  false,
				},
				{
					OID:          "1.3.6.1.4.1.9.2.1.58.0",
					Description:  "IOS Average CPU (5 min)",
					Weight:       40,
					IsDefinitive: false,
					MustRespond:  false,
				},
				{
					OID:          "1.3.6.1.2.1.47.1.1.1.1.9.1001",
					Description:  "IOS Version",
					Weight:       50,
					IsDefinitive: false,
					MustRespond:  false,
				},
			},
			RequiredPatterns:  []string{"cisco", "ios"},
			ExclusionPatterns: []string{"ion 3000", "lexmark", "aruba"},
			MinConfidence:     30,
			FallbackPatterns:  []string{"catalyst", "nexus", "cupertino"},
		},
		{
			Vendor:   "palo_alto",
			Priority: 5,
			ValidatorOIDs: []ValidatorOID{
				{
					OID:            "1.3.6.1.4.1.25461.2.3.36",
					Description:    "Palo Alto Device Identifier",
					Weight:         90,
					IsDefinitive:   true,
					MustRespond:    false,
				},
				{
					OID:            "1.3.6.1.4.1.25461.2.1.2.1.14.0",
					ExpectedValues: []string{"paloaltonetworks"},
					Description:    "Palo Alto Vendor Verification",
					Weight:         95,
					IsDefinitive:   true,
					MustRespond:    false,
				},
				{
					OID:         "1.3.6.1.4.1.25461.2.1.2.1.1.0",
					Description: "Palo Alto OS Version",
					Weight:      60,
					IsDefinitive: false,
					MustRespond: false,
				},
			},
			RequiredPatterns:  []string{"palo alto", "pan-os"},
			ExclusionPatterns: []string{"ion", "cloudgenix", "cisco"},
			MinConfidence:     40,
			FallbackPatterns:  []string{"panorama"},
		},
		{
			Vendor:   "ion",
			Priority: 8,
			ValidatorOIDs: []ValidatorOID{
				{
					OID:          "1.3.6.1.4.1.50114.11.1.10.3000",
					Description:  "ION 3000 Model Identifier",
					Weight:       95,
					IsDefinitive: true,
					MustRespond:  false,
				},
			},
			RequiredPatterns:  []string{"ion 3000"},
			ExclusionPatterns: []string{"cisco", "palo alto", "arista"},
			MinConfidence:     50,
			FallbackPatterns:  []string{},
		},
		{
			Vendor:   "bluecat",
			Priority: 7,
			ValidatorOIDs: []ValidatorOID{
				{
					OID:          "1.3.6.1.4.1.13315.2.1",
					Description:  "BlueCat System Info",
					Weight:       90,
					IsDefinitive: true,
					MustRespond:  false,
				},
			},
			RequiredPatterns:  []string{"bluecat"},
			ExclusionPatterns: []string{"cisco", "aruba"},
			MinConfidence:     50,
			FallbackPatterns:  []string{"adonis", "proteus"},
		},
		{
			Vendor:   "arista",
			Priority: 15,
			ValidatorOIDs: []ValidatorOID{
				{
					OID:          "1.3.6.1.4.1.30065.3.1.1.0",
					Description:  "Arista EOS Version",
					Weight:       85,
					IsDefinitive: true,
					MustRespond:  false,
				},
			},
			RequiredPatterns:  []string{"arista", "eos"},
			ExclusionPatterns: []string{"cisco", "lexmark"},
			MinConfidence:     40,
			FallbackPatterns:  []string{},
		},
		{
			Vendor:   "lexmark",
			Priority: 3,
			ValidatorOIDs: []ValidatorOID{
				{
					OID:          "1.3.6.1.4.1.641.2.1.2.1.2.1",
					Description:  "Lexmark Printer Model",
					Weight:       90,
					IsDefinitive: true,
					MustRespond:  false,
				},
			},
			RequiredPatterns:  []string{"lexmark"},
			ExclusionPatterns: []string{"aruba", "cisco", "switch"},
			MinConfidence:     50,
			FallbackPatterns:  []string{"mx822", "cx943", "printer"},
		},
	}
}

// Note: To fully replace DetectVendorComprehensive, you would need to modify detector.go directly
// For now, use DetectVendorAdvanced() directly in your client code