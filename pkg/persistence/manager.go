// pkg/persistence/manager.go
package persistence

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// PersistenceManager handles all database operations
type PersistenceManager struct {
	dbPath          string
	backupDir       string
	database        *DeviceDatabase
	mutex           sync.RWMutex
	autoSave        bool
	saveInterval    time.Duration
	stopAutoSave    chan bool
	autoSaveRunning bool
	dirty           bool // Tracks if database has unsaved changes
}

// NewPersistenceManager creates a new persistence manager
func NewPersistenceManager(dbPath string) *PersistenceManager {
	pm := &PersistenceManager{
		dbPath:       dbPath,
		backupDir:    filepath.Join(filepath.Dir(dbPath), "backups"),
		database:     NewDeviceDatabase(),
		autoSave:     true,
		saveInterval: 30 * time.Second,
		stopAutoSave: make(chan bool),
		dirty:        false,
	}

	// Ensure backup directory exists
	os.MkdirAll(pm.backupDir, 0755)

	return pm
}

// LoadDatabase loads the database from disk, creating a new one if it doesn't exist
func (pm *PersistenceManager) LoadDatabase() error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	if _, err := os.Stat(pm.dbPath); os.IsNotExist(err) {
		// Create new database
		pm.database = NewDeviceDatabase()
		pm.dirty = true
		return pm.saveDatabase()
	}

	file, err := os.Open(pm.dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database file: %w", err)
	}
	defer file.Close()

	// Try to detect if file is gzipped
	var reader io.Reader = file

	// Read first few bytes to check for gzip magic number
	file.Seek(0, 0)
	header := make([]byte, 2)
	file.Read(header)
	file.Seek(0, 0)

	if header[0] == 0x1f && header[1] == 0x8b {
		// File is gzipped
		gzReader, err := gzip.NewReader(file)
		if err != nil {
			return fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer gzReader.Close()
		reader = gzReader
	}

	decoder := json.NewDecoder(reader)
	if err := decoder.Decode(pm.database); err != nil {
		return fmt.Errorf("failed to decode database: %w", err)
	}

	pm.dirty = false
	return nil
}

// SaveDatabase saves the current database to disk
func (pm *PersistenceManager) SaveDatabase() error {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	if !pm.dirty {
		return nil // No changes to save
	}

	return pm.saveDatabase()
}

// saveDatabase performs the actual save operation (assumes lock is held)
func (pm *PersistenceManager) saveDatabase() error {
	// Update metadata before saving
	pm.database.LastUpdated = time.Now()
	pm.database.TotalDevices = len(pm.database.Devices)
	pm.database.UpdateStatistics()

	// Create backup before saving new version
	if pm.database.Config.BackupEnabled {
		pm.createBackup()
	}

	// Create temporary file for atomic write
	tempPath := pm.dbPath + ".tmp"

	file, err := os.Create(tempPath)
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	defer os.Remove(tempPath) // Clean up temp file if something goes wrong

	var writer io.Writer = file

	// Use compression if enabled
	if pm.database.Config.CompressBackups {
		gzWriter := gzip.NewWriter(file)
		defer gzWriter.Close()
		writer = gzWriter
	}

	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ") // Pretty print for readability

	if err := encoder.Encode(pm.database); err != nil {
		file.Close()
		return fmt.Errorf("failed to encode database: %w", err)
	}

	file.Close()

	// Atomic move
	if err := os.Rename(tempPath, pm.dbPath); err != nil {
		return fmt.Errorf("failed to move temporary file: %w", err)
	}

	pm.dirty = false
	return nil
}

// createBackup creates a backup of the current database file
func (pm *PersistenceManager) createBackup() error {
	if _, err := os.Stat(pm.dbPath); os.IsNotExist(err) {
		return nil // No existing file to backup
	}

	timestamp := time.Now().Format("20060102_150405")
	backupPath := filepath.Join(pm.backupDir, fmt.Sprintf("database_%s.json", timestamp))

	if pm.database.Config.CompressBackups {
		backupPath += ".gz"
	}

	// Copy current database to backup location
	sourceFile, err := os.Open(pm.dbPath)
	if err != nil {
		return fmt.Errorf("failed to open source file for backup: %w", err)
	}
	defer sourceFile.Close()

	backupFile, err := os.Create(backupPath)
	if err != nil {
		return fmt.Errorf("failed to create backup file: %w", err)
	}
	defer backupFile.Close()

	var writer io.Writer = backupFile
	if pm.database.Config.CompressBackups {
		gzWriter := gzip.NewWriter(backupFile)
		defer gzWriter.Close()
		writer = gzWriter
	}

	_, err = io.Copy(writer, sourceFile)
	if err != nil {
		return fmt.Errorf("failed to copy data to backup: %w", err)
	}

	// Clean up old backups
	pm.cleanupOldBackups()

	return nil
}

// cleanupOldBackups removes old backup files beyond the configured limit
func (pm *PersistenceManager) cleanupOldBackups() error {
	if pm.database.Config.BackupCount <= 0 {
		return nil
	}

	files, err := os.ReadDir(pm.backupDir)
	if err != nil {
		return err
	}

	// Filter backup files
	var backupFiles []os.DirEntry
	for _, file := range files {
		if !file.IsDir() && (filepath.Ext(file.Name()) == ".json" || filepath.Ext(file.Name()) == ".gz") {
			backupFiles = append(backupFiles, file)
		}
	}

	// If we have more backups than configured, remove oldest ones
	if len(backupFiles) > pm.database.Config.BackupCount {
		// Sort by modification time (oldest first)
		// Note: This is a simplified version, you might want to sort by filename timestamp
		filesToDelete := len(backupFiles) - pm.database.Config.BackupCount

		for i := 0; i < filesToDelete; i++ {
			filePath := filepath.Join(pm.backupDir, backupFiles[i].Name())
			os.Remove(filePath)
		}
	}

	return nil
}

// StartAutoSave begins automatic saving at the configured interval
func (pm *PersistenceManager) StartAutoSave() {
	if pm.autoSaveRunning {
		return
	}

	pm.autoSaveRunning = true
	go pm.autoSaveLoop()
}

// StopAutoSave stops the automatic saving
func (pm *PersistenceManager) StopAutoSave() {
	if !pm.autoSaveRunning {
		return
	}

	pm.stopAutoSave <- true
	pm.autoSaveRunning = false
}

// autoSaveLoop runs the automatic save process
func (pm *PersistenceManager) autoSaveLoop() {
	ticker := time.NewTicker(pm.saveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if pm.dirty {
				if err := pm.SaveDatabase(); err != nil {
					// Log error but continue running
					fmt.Printf("Auto-save failed: %v\n", err)
				}
			}
		case <-pm.stopAutoSave:
			// Final save before stopping
			if pm.dirty {
				pm.SaveDatabase()
			}
			return
		}
	}
}

// GetDatabase returns a read-only copy of the current database
func (pm *PersistenceManager) GetDatabase() *DeviceDatabase {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	// Return a copy to prevent external modifications
	data, _ := json.Marshal(pm.database)
	var copy DeviceDatabase
	json.Unmarshal(data, &copy)
	return &copy
}

// GetDevice returns a specific device by ID
func (pm *PersistenceManager) GetDevice(deviceID string) (*Device, bool) {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	device, exists := pm.database.Devices[deviceID]
	if !exists {
		return nil, false
	}

	// Return a copy
	data, _ := json.Marshal(device)
	var copy Device
	json.Unmarshal(data, &copy)
	return &copy, true
}

// GetAllDevices returns all devices as a slice
func (pm *PersistenceManager) GetAllDevices() []Device {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	devices := make([]Device, 0, len(pm.database.Devices))
	for _, device := range pm.database.Devices {
		devices = append(devices, device)
	}

	return devices
}

// GetDevicesByVendor returns devices filtered by vendor
func (pm *PersistenceManager) GetDevicesByVendor(vendor string) []Device {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	var devices []Device
	for _, device := range pm.database.Devices {
		if device.Vendor == vendor {
			devices = append(devices, device)
		}
	}

	return devices
}

// GetDevicesBySubnet returns devices in a specific subnet
func (pm *PersistenceManager) GetDevicesBySubnet(subnet string) []Device {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	var devices []Device
	for _, device := range pm.database.Devices {
		if device.GetSubnet() == subnet {
			devices = append(devices, device)
		}
	}

	return devices
}

// GetRecentSessions returns the most recent scan sessions
func (pm *PersistenceManager) GetRecentSessions(limit int) []ScanSession {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	sessions := pm.database.Sessions
	if len(sessions) <= limit {
		return sessions
	}

	// Return the most recent sessions
	return sessions[len(sessions)-limit:]
}

// AddDevice adds or updates a device in the database
func (pm *PersistenceManager) AddDevice(device Device) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	pm.database.Devices[device.ID] = device
	pm.dirty = true
}

// RemoveDevice removes a device from the database
func (pm *PersistenceManager) RemoveDevice(deviceID string) bool {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	if _, exists := pm.database.Devices[deviceID]; exists {
		delete(pm.database.Devices, deviceID)
		pm.dirty = true
		return true
	}

	return false
}

// AddSession adds a scan session to the database
func (pm *PersistenceManager) AddSession(session ScanSession) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	pm.database.Sessions = append(pm.database.Sessions, session)

	// Limit session history
	if len(pm.database.Sessions) > pm.database.Config.MaxSessions {
		// Remove oldest sessions
		excess := len(pm.database.Sessions) - pm.database.Config.MaxSessions
		pm.database.Sessions = pm.database.Sessions[excess:]
	}

	pm.dirty = true
}

// GetStatistics returns current database statistics
func (pm *PersistenceManager) GetStatistics() DatabaseStats {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	return pm.database.Statistics
}

// SetConfig updates database configuration
func (pm *PersistenceManager) SetConfig(config DatabaseConfig) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	pm.database.Config = config
	pm.dirty = true
}

// GetConfig returns current database configuration
func (pm *PersistenceManager) GetConfig() DatabaseConfig {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	return pm.database.Config
}

// Cleanup performs database maintenance tasks
func (pm *PersistenceManager) Cleanup() error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	var cleaned int

	// Remove devices that haven't been seen in a long time (if auto cleanup enabled)
	if pm.database.Config.AutoCleanup {
		cutoff := time.Now().Add(-30 * 24 * time.Hour) // 30 days

		for id, device := range pm.database.Devices {
			if device.LastSeen.Before(cutoff) && device.ScanCount < 3 {
				delete(pm.database.Devices, id)
				cleaned++
			}
		}
	}

	// Limit total devices if needed
	if len(pm.database.Devices) > pm.database.Config.MaxDevices {
		// This is a simplified cleanup - in production you might want more sophisticated logic
		excess := len(pm.database.Devices) - pm.database.Config.MaxDevices
		count := 0

		for id, device := range pm.database.Devices {
			if count >= excess {
				break
			}

			// Remove devices with low confidence and few scans
			if device.ConfidenceScore < 50 && device.ScanCount < 3 {
				delete(pm.database.Devices, id)
				count++
				cleaned++
			}
		}
	}

	if cleaned > 0 {
		pm.dirty = true
		fmt.Printf("Cleanup: removed %d devices\n", cleaned)
	}

	return nil
}

// Close properly shuts down the persistence manager
func (pm *PersistenceManager) Close() error {
	pm.StopAutoSave()
	return pm.SaveDatabase()
}
