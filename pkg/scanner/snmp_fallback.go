package main

import (
	"fmt"
	"time"

	"github.com/scottpeterman/gosnmptk/pkg/snmp"
)

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

// testSNMPWithFallback performs intelligent SNMP version testing with automatic fallback
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

	// Add explicitly configured community first
	if s.config.Community != "" {
		communitiesToTry = append(communitiesToTry, s.config.Community)
	}

	// Add other communities if not already included
	for _, community := range s.config.Communities {
		if community != s.config.Community {
			communitiesToTry = append(communitiesToTry, community)
		}
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
