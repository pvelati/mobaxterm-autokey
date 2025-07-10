package main

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// LicenseType represents the different types of licenses available
type LicenseType int

const (
	Professional LicenseType = 1 // Professional license with full features
	Educational  LicenseType = 3 // Educational license with limited features
	Personal     LicenseType = 4 // Personal license for individual use
)

// String method for LicenseType to provide readable output
func (lt LicenseType) String() string {
	switch lt {
	case Professional:
		return "Professional"
	case Educational:
		return "Educational"
	case Personal:
		return "Personal"
	default:
		return "Unknown"
	}
}

// Custom base64 variant table - uses standard base64 alphabet
// This appears to be a custom encoding scheme rather than standard base64
var variantTable = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")

// variantBase64Encode encodes data using a custom base64-like algorithm
// This is NOT standard base64 encoding - it processes data in 3-byte chunks
// and encodes them as 4 characters using little-endian byte order
func variantBase64Encode(data []byte) []byte {
	var buf bytes.Buffer

	// Process complete 3-byte blocks
	blocks := len(data) / 3
	remainder := len(data) % 3

	// Encode each 3-byte block as 4 characters
	for i := 0; i < blocks; i++ {
		chunk := data[i*3 : i*3+3]

		// Pad to 4 bytes for little-endian uint32 conversion
		padded := make([]byte, 4)
		copy(padded, chunk)

		// Convert to uint32 in little-endian format
		val := int(binary.LittleEndian.Uint32(padded))

		// Extract 6-bit values and map to custom alphabet
		buf.WriteByte(variantTable[val&0x3f])       // bits 0-5
		buf.WriteByte(variantTable[(val>>6)&0x3f])  // bits 6-11
		buf.WriteByte(variantTable[(val>>12)&0x3f]) // bits 12-17
		buf.WriteByte(variantTable[(val>>18)&0x3f]) // bits 18-23
	}

	// Handle remaining bytes (1 or 2 bytes)
	if remainder > 0 {
		tail := data[blocks*3:]
		padded := make([]byte, 4)
		copy(padded, tail)

		val := int(binary.LittleEndian.Uint32(padded))
		buf.WriteByte(variantTable[val&0x3f])
		buf.WriteByte(variantTable[(val>>6)&0x3f])

		// Only add third character if we have 2 remaining bytes
		if remainder == 2 {
			buf.WriteByte(variantTable[(val>>12)&0x3f])
		}
	}

	return buf.Bytes()
}

// encryptBytes performs a simple XOR encryption with a rolling key
// The algorithm XORs each byte with the high byte of the key,
// then updates the key based on the encrypted result
func encryptBytes(key uint16, data []byte) []byte {
	if len(data) == 0 {
		return nil
	}

	out := make([]byte, len(data))

	for i := range data {
		// Extract high byte of key for XOR operation
		x := byte((key >> 8) & 0xff)

		// XOR the data byte with the key byte
		out[i] = data[i] ^ x

		// Update key: combine encrypted byte with current key using OR operation
		// The constant 0x482D appears to be a magic number for key transformation
		key = (uint16(out[i]) & key) | 0x482D
	}

	return out
}

// VS_FIXEDFILEINFO represents the Windows version information structure
// This structure contains file version details from Windows PE resources
type VS_FIXEDFILEINFO struct {
	Signature        uint32 // Should be 0xFEEF04BD
	StrucVersion     uint32 // Structure version
	FileVersionMS    uint32 // Most significant 32 bits of file version
	FileVersionLS    uint32 // Least significant 32 bits of file version
	ProductVersionMS uint32 // Most significant 32 bits of product version
	ProductVersionLS uint32 // Least significant 32 bits of product version
	FileFlagsMask    uint32 // Bitmask for file flags
	FileFlags        uint32 // File flags (debug, patched, etc.)
	FileOS           uint32 // Operating system for which file was designed
	FileType         uint32 // General type of file
	FileSubtype      uint32 // Function of the file
	FileDateMS       uint32 // Most significant 32 bits of file date
	FileDateLS       uint32 // Least significant 32 bits of file date
}

// getFileVersion extracts version information from a Windows executable file
// Uses Windows API calls to read version resources from PE files
func getFileVersion(filePath string) (string, error) {
	if filePath == "" {
		return "", fmt.Errorf("file path cannot be empty")
	}

	// Load version.dll for accessing version information APIs
	dll := syscall.NewLazyDLL("version.dll")
	procGetFileVersionInfoSizeW := dll.NewProc("GetFileVersionInfoSizeW")
	procGetFileVersionInfoW := dll.NewProc("GetFileVersionInfoW")
	procVerQueryValueW := dll.NewProc("VerQueryValueW")

	// Convert file path to UTF-16 for Windows API
	pathPtr, err := syscall.UTF16PtrFromString(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to create UTF-16 pointer: %w", err)
	}

	// Step 1: Get the size of version information buffer
	size, _, err := procGetFileVersionInfoSizeW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(0),
	)
	if size == 0 {
		return "", fmt.Errorf("no version info found for file: %s", filePath)
	}

	// Step 2: Allocate buffer and retrieve version information
	data := make([]byte, size)
	ok, _, err := procGetFileVersionInfoW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		0,
		uintptr(size),
		uintptr(unsafe.Pointer(&data[0])),
	)
	if ok == 0 {
		return "", fmt.Errorf("failed to get version info: %w", err)
	}

	// Step 3: Query the fixed file information structure
	var block *uint16
	blockName, err := syscall.UTF16PtrFromString(`\`)
	if err != nil {
		return "", fmt.Errorf("failed to create UTF-16 pointer for block name: %w", err)
	}

	var fixedInfo *VS_FIXEDFILEINFO
	var blockLen uint32
	r, _, err := procVerQueryValueW.Call(
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(unsafe.Pointer(blockName)),
		uintptr(unsafe.Pointer(&block)),
		uintptr(unsafe.Pointer(&blockLen)),
	)
	if r == 0 {
		return "", fmt.Errorf("failed to query version block: %w", err)
	}

	// Extract version information from the structure
	fixedInfo = (*VS_FIXEDFILEINFO)(unsafe.Pointer(block))

	// FileVersionMS contains major version in high 16 bits, minor in low 16 bits
	major := fixedInfo.FileVersionMS >> 16
	minor := fixedInfo.FileVersionMS & 0xFFFF

	return fmt.Sprintf("%d.%d", major, minor), nil
}

// generateLicense creates a license file with encrypted license data
// The license format appears to be: type#username|version#count#magic#zeros#
func generateLicense(licType LicenseType, count int, userName string, major, minor int) error {
	// Validate input parameters
	if userName == "" {
		return fmt.Errorf("username cannot be empty")
	}
	if count <= 0 {
		return fmt.Errorf("count must be positive")
	}
	if major < 0 || minor < 0 {
		return fmt.Errorf("version numbers must be non-negative")
	}

	// Generate license string with specific format
	// Format: type#username|majorminor#count#major3minor6minor#0#0#0#
	licenseString := fmt.Sprintf("%d#%s|%d%d#%d#%d3%d6%d#%d#%d#%d#",
		licType, userName, major, minor, count,
		major, minor, minor, 0, 0, 0)

	// Encrypt the license string using custom XOR encryption
	encrypted := encryptBytes(0x787, []byte(licenseString))

	// Encode with custom base64 variant
	encoded := variantBase64Encode(encrypted)

	// Create the license file as a ZIP archive
	return createLicenseZip(encoded)
}

// createLicenseZip creates a ZIP file containing the encoded license data
func createLicenseZip(encoded []byte) error {
	// Create the output file
	f, err := os.Create("Custom.mxtpro")
	if err != nil {
		return fmt.Errorf("failed to create license file: %w", err)
	}
	defer f.Close()

	// Create ZIP writer
	zipWriter := zip.NewWriter(f)
	defer zipWriter.Close()

	// Create ZIP header with exact specifications
	now := time.Now()
	header := &zip.FileHeader{
		Name:               "Pro.key",
		Method:             zip.Store, // No compression - store as-is
		CompressedSize64:   uint64(len(encoded)),
		UncompressedSize64: uint64(len(encoded)),
		Modified:           now,
		CRC32:              crc32.ChecksumIEEE(encoded), // Calculate CRC32 checksum
	}
	header.SetModTime(now)

	// Create file in ZIP archive
	proFile, err := zipWriter.CreateRaw(header)
	if err != nil {
		return fmt.Errorf("failed to create file in ZIP archive: %w", err)
	}

	// Write encoded data to ZIP file
	_, err = proFile.Write(encoded)
	if err != nil {
		return fmt.Errorf("failed to write data to ZIP file: %w", err)
	}

	return nil
}

// findMobaXtermExe searches for MobaXterm executable files in current directory
// Returns the first matching file found
func findMobaXtermExe() (string, error) {
	// Search for files matching the pattern MobaXterm*.exe
	files, err := filepath.Glob("MobaXterm*.exe")
	if err != nil {
		return "", fmt.Errorf("error searching for MobaXterm executable files: %w", err)
	}

	if len(files) == 0 {
		return "", fmt.Errorf("no MobaXterm*.exe files found in current directory")
	}

	// Return the first match (could be improved to select most recent version)
	return files[0], nil
}

// parseVersion parses a version string in format "major.minor"
func parseVersion(versionStr string) (major, minor int, err error) {
	parts := strings.Split(versionStr, ".")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid version format: %s (expected major.minor)", versionStr)
	}

	major, err = strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("failed to parse major version: %w", err)
	}

	minor, err = strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, fmt.Errorf("failed to parse minor version: %w", err)
	}

	return major, minor, nil
}

// waitToExit prompts user to press any key before closing the terminal
func waitToExit() {
	fmt.Print("\nPress Enter to close terminal...")
	fmt.Scanln()
}

// main function orchestrates the license generation process
func main() {
	fmt.Println("MobaXterm AutoKey")
	fmt.Println("=================")

	// Step 1: Find MobaXterm executable
	fmt.Println("[*] Searching for MobaXterm executable...")
	exePath, err := findMobaXtermExe()
	if err != nil {
		fmt.Printf("[!] Error finding MobaXterm executable: %v\n", err)
		waitToExit()
		return
	}

	// Step 2: Extract version information
	fmt.Printf("[*] Reading version from: %s\n", exePath)
	versionStr, err := getFileVersion(exePath)
	if err != nil {
		fmt.Printf("[!] Error reading version: %v\n", err)
		waitToExit()
		return
	}

	// Step 3: Parse version string
	fmt.Printf("[+] Version detected: %s\n", versionStr)
	major, minor, err := parseVersion(versionStr)
	if err != nil {
		fmt.Printf("[!] Error parsing version: %v\n", err)
		waitToExit()
		return
	}

	// Step 4: Generate license
	const username = "registered_user"
	const licenseCount = 1

	fmt.Printf("[*] Generating %s license for %s (version %d.%d)...\n",
		Professional, username, major, minor)

	err = generateLicense(Professional, licenseCount, username, major, minor)
	if err != nil {
		fmt.Printf("[!] Error generating license: %v\n", err)
	} else {
		fmt.Println("[+] License file 'Custom.mxtpro' generated successfully!")
	}

	waitToExit()
}
