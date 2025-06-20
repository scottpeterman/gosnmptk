package snmp

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

// Client represents an SNMP client with connection settings
type Client struct {
	Target    string
	Port      uint16
	Community string
	Version   gosnmp.SnmpVersion
	Timeout   time.Duration
	Retries   int

	// SNMPv3 settings
	Username         string
	AuthProtocol     gosnmp.SnmpV3AuthProtocol
	AuthPassphrase   string
	PrivProtocol     gosnmp.SnmpV3PrivProtocol
	PrivPassphrase   string
	SecurityLevel    gosnmp.SnmpV3MsgFlags
	ContextName      string
	SecurityModel    gosnmp.SnmpV3SecurityModel
	SecurityUsername string

	conn *gosnmp.GoSNMP
}

// NewClient creates a new SNMP client with default settings
func NewClient(target string, port uint16) *Client {
	return &Client{
		Target:    target,
		Port:      port,
		Community: "public",
		Version:   gosnmp.Version2c,
		Timeout:   time.Second * 5,
		Retries:   2,
	}
}

// NewSNMPv3Client creates a new SNMPv3 client
func NewSNMPv3Client(target string, port uint16, username, authKey, privKey string) *Client {
	return &Client{
		Target:           target,
		Port:             port,
		Version:          gosnmp.Version3,
		Timeout:          time.Second * 5,
		Retries:          2,
		Username:         username,
		AuthProtocol:     gosnmp.SHA,
		AuthPassphrase:   authKey,
		PrivProtocol:     gosnmp.AES,
		PrivPassphrase:   privKey,
		SecurityLevel:    gosnmp.AuthPriv,
		SecurityModel:    gosnmp.UserSecurityModel,
		SecurityUsername: username,
	}
}

// Connect establishes the SNMP connection
func (c *Client) Connect() error {
	// Validate IP address
	if net.ParseIP(c.Target) == nil {
		return fmt.Errorf("invalid IP address: %s", c.Target)
	}

	// Create GoSNMP instance
	c.conn = &gosnmp.GoSNMP{
		Target:    c.Target,
		Port:      c.Port,
		Community: c.Community,
		Version:   c.Version,
		Timeout:   c.Timeout,
		Retries:   c.Retries,
	}

	// Configure SNMPv3 if needed
	if c.Version == gosnmp.Version3 {
		c.conn.SecurityModel = c.SecurityModel
		c.conn.MsgFlags = c.SecurityLevel
		c.conn.SecurityParameters = &gosnmp.UsmSecurityParameters{
			UserName:                 c.Username,
			AuthenticationProtocol:   c.AuthProtocol,
			AuthenticationPassphrase: c.AuthPassphrase,
			PrivacyProtocol:          c.PrivProtocol,
			PrivacyPassphrase:        c.PrivPassphrase,
		}
	}

	// Connect
	err := c.conn.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to %s:%d: %w", c.Target, c.Port, err)
	}

	return nil
}

// Close closes the SNMP connection
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Conn.Close()
	}
	return nil
}

// Get performs an SNMP GET operation
func (c *Client) Get(oid string) (string, error) {
	if c.conn == nil {
		return "", fmt.Errorf("not connected")
	}

	result, err := c.conn.Get([]string{oid})
	if err != nil {
		return "", fmt.Errorf("SNMP GET failed for OID %s: %w", oid, err)
	}

	if len(result.Variables) == 0 {
		return "", fmt.Errorf("no result for OID %s", oid)
	}

	variable := result.Variables[0]
	return c.formatValue(variable), nil
}

// GetNext performs an SNMP GETNEXT operation
func (c *Client) GetNext(oid string) (string, string, error) {
	if c.conn == nil {
		return "", "", fmt.Errorf("not connected")
	}

	result, err := c.conn.GetNext([]string{oid})
	if err != nil {
		return "", "", fmt.Errorf("SNMP GETNEXT failed for OID %s: %w", oid, err)
	}

	if len(result.Variables) == 0 {
		return "", "", fmt.Errorf("no result for OID %s", oid)
	}

	variable := result.Variables[0]
	return variable.Name, c.formatValue(variable), nil
}

// GetBulk performs an SNMP GETBULK operation
func (c *Client) GetBulk(oid string, nonRepeaters, maxRepetitions uint8) ([]SNMPVariable, error) {
	if c.conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	// gosnmp expects: nonRepeaters as uint8, maxRepetitions as uint32
	result, err := c.conn.GetBulk([]string{oid}, nonRepeaters, uint32(maxRepetitions))
	if err != nil {
		return nil, fmt.Errorf("SNMP GETBULK failed for OID %s: %w", oid, err)
	}

	variables := make([]SNMPVariable, len(result.Variables))
	for i, variable := range result.Variables {
		variables[i] = SNMPVariable{
			OID:   variable.Name,
			Value: c.formatValue(variable),
			Type:  variable.Type.String(),
		}
	}

	return variables, nil
}

// Walk performs an SNMP walk operation
func (c *Client) Walk(oid string) ([]SNMPVariable, error) {
	if c.conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	var results []SNMPVariable

	err := c.conn.Walk(oid, func(variable gosnmp.SnmpPDU) error {
		results = append(results, SNMPVariable{
			OID:   variable.Name,
			Value: c.formatValue(variable),
			Type:  variable.Type.String(),
		})
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("SNMP WALK failed for OID %s: %w", oid, err)
	}

	return results, nil
}

// BulkWalk performs an SNMP bulk walk operation
func (c *Client) BulkWalk(oid string, maxRepetitions uint8) ([]SNMPVariable, error) {
	if c.conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	var results []SNMPVariable

	err := c.conn.BulkWalk(oid, func(variable gosnmp.SnmpPDU) error {
		results = append(results, SNMPVariable{
			OID:   variable.Name,
			Value: c.formatValue(variable),
			Type:  variable.Type.String(),
		})
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("SNMP BULKWALK failed for OID %s: %w", oid, err)
	}

	return results, nil
}

// TestConnection tests the SNMP connection using sysDescr
func (c *Client) TestConnection() (string, error) {
	return c.Get("1.3.6.1.2.1.1.1.0") // sysDescr
}

// GetBasicInfo retrieves basic system information
func (c *Client) GetBasicInfo() (*BasicInfo, error) {
	basicOIDs := map[string]string{
		"sysDescr":    "1.3.6.1.2.1.1.1.0",
		"sysObjectID": "1.3.6.1.2.1.1.2.0",
		"sysUpTime":   "1.3.6.1.2.1.1.3.0",
		"sysContact":  "1.3.6.1.2.1.1.4.0",
		"sysName":     "1.3.6.1.2.1.1.5.0",
		"sysLocation": "1.3.6.1.2.1.1.6.0",
		"sysServices": "1.3.6.1.2.1.1.7.0",
	}

	info := &BasicInfo{}

	for name, oid := range basicOIDs {
		value, err := c.Get(oid)
		if err != nil {
			// Log error but continue with other OIDs
			continue
		}

		switch name {
		case "sysDescr":
			info.SystemDescription = value
		case "sysObjectID":
			info.SystemObjectID = value
		case "sysUpTime":
			info.SystemUptime = value
		case "sysContact":
			info.SystemContact = value
		case "sysName":
			info.SystemName = value
		case "sysLocation":
			info.SystemLocation = value
		case "sysServices":
			info.SystemServices = value
		}
	}

	return info, nil
}

// formatValue formats an SNMP variable value as a string
func (c *Client) formatValue(variable gosnmp.SnmpPDU) string {
	switch variable.Type {
	case gosnmp.OctetString:
		if bytes, ok := variable.Value.([]byte); ok {
			// Try to convert to string, handling potential binary data
			return string(bytes)
		}
		return fmt.Sprintf("%v", variable.Value)
	case gosnmp.Integer:
		return fmt.Sprintf("%d", variable.Value)
	case gosnmp.Counter32, gosnmp.Counter64, gosnmp.Gauge32:
		return fmt.Sprintf("%d", variable.Value)
	case gosnmp.TimeTicks:
		if ticks, ok := variable.Value.(uint32); ok {
			// Convert ticks to duration (1 tick = 10ms)
			duration := time.Duration(ticks) * 10 * time.Millisecond
			return fmt.Sprintf("%s (%d ticks)", duration.String(), ticks)
		}
		return fmt.Sprintf("%v", variable.Value)
	case gosnmp.ObjectIdentifier:
		return fmt.Sprintf("%v", variable.Value)
	case gosnmp.IPAddress:
		if bytes, ok := variable.Value.([]byte); ok && len(bytes) == 4 {
			return fmt.Sprintf("%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3])
		}
		return fmt.Sprintf("%v", variable.Value)
	default:
		return fmt.Sprintf("%v", variable.Value)
	}
}

// SNMPVariable represents an SNMP variable
type SNMPVariable struct {
	OID   string `json:"oid"`
	Value string `json:"value"`
	Type  string `json:"type"`
}

// BasicInfo represents basic SNMP system information
type BasicInfo struct {
	SystemDescription string `json:"system_description"`
	SystemObjectID    string `json:"system_object_id"`
	SystemUptime      string `json:"system_uptime"`
	SystemContact     string `json:"system_contact"`
	SystemName        string `json:"system_name"`
	SystemLocation    string `json:"system_location"`
	SystemServices    string `json:"system_services"`
}

// AuthProtocolFromString converts string to gosnmp auth protocol
func AuthProtocolFromString(protocol string) gosnmp.SnmpV3AuthProtocol {
	switch strings.ToUpper(protocol) {
	case "MD5":
		return gosnmp.MD5
	case "SHA":
		return gosnmp.SHA
	case "SHA224":
		return gosnmp.SHA224
	case "SHA256":
		return gosnmp.SHA256
	case "SHA384":
		return gosnmp.SHA384
	case "SHA512":
		return gosnmp.SHA512
	default:
		return gosnmp.NoAuth
	}
}

// PrivProtocolFromString converts string to gosnmp priv protocol
func PrivProtocolFromString(protocol string) gosnmp.SnmpV3PrivProtocol {
	switch strings.ToUpper(protocol) {
	case "DES":
		return gosnmp.DES
	case "AES", "AES128":
		return gosnmp.AES
	case "AES192":
		return gosnmp.AES192
	case "AES256":
		return gosnmp.AES256
	default:
		return gosnmp.NoPriv
	}
}

// ParseTimeout parses a timeout string to time.Duration
func ParseTimeout(timeoutStr string) (time.Duration, error) {
	if timeoutStr == "" {
		return time.Second * 5, nil
	}

	// Try parsing as float (seconds)
	if seconds, err := strconv.ParseFloat(timeoutStr, 64); err == nil {
		return time.Duration(seconds * float64(time.Second)), nil
	}

	// Try parsing as duration string
	return time.ParseDuration(timeoutStr)
}
