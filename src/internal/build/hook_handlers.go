package build

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/rapidfort/smithy/pkg/logger"
)

// ContainerState represents OCI container state passed to hooks
type ContainerState struct {
	OCIVersion  string            `json:"ociVersion"`
	ID          string            `json:"id"`
	Status      string            `json:"status"`
	PID         int               `json:"pid"`
	Bundle      string            `json:"bundle"`
	Root        string            `json:"root"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// HandlePrestartHook is called by the prestart OCI hook
// It injects strace into the container before it starts
func HandlePrestartHook(outputDir string) error {
	// Always log to file for debugging
	logFile, _ := os.OpenFile("/tmp/smithy-prestart-hook.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if logFile != nil {
		defer logFile.Close()
		fmt.Fprintf(logFile, "\n=== PRESTART HOOK CALLED at %s ===\n", time.Now().Format(time.RFC3339))
		fmt.Fprintf(logFile, "OutputDir: %s\n", outputDir)
	}
	
	logger.Info("=== PRESTART HOOK CALLED ===")
	
	// Test: Touch a file to prove hook is running
	testFile := "/tmp/hook-prestart-ran.txt"
	if err := os.WriteFile(testFile, []byte("prestart hook executed\n"), 0644); err != nil {
		logger.Warning("Failed to write test file: %v", err)
		if logFile != nil {
			fmt.Fprintf(logFile, "ERROR: Failed to write test file: %v\n", err)
		}
	}
	
	// Read container state from stdin (OCI spec requirement)
	state, err := readContainerState()
	if err != nil {
		msg := fmt.Sprintf("Failed to read container state: %v", err)
		logger.Error(msg)
		if logFile != nil {
			fmt.Fprintf(logFile, "ERROR: %s\n", msg)
		}
		return fmt.Errorf("failed to read container state: %v", err)
	}

	if logFile != nil {
		fmt.Fprintf(logFile, "Container ID: %s\n", state.ID)
		fmt.Fprintf(logFile, "Bundle: %s\n", state.Bundle)
	}

	logger.Info("Prestart hook for container: %s", state.ID)
	logger.Info("Bundle path: %s", state.Bundle)

	// Get paths from container state
	// Use state.Root which is the actual rootfs path
	rootfs := state.Root
	if rootfs == "" {
		// Fallback to old method
		rootfs = filepath.Join(state.Bundle, "rootfs")
	}
	configPath := filepath.Join(state.Bundle, "config.json")

	if logFile != nil {
		fmt.Fprintf(logFile, "Rootfs: %s\n", rootfs)
		fmt.Fprintf(logFile, "Config: %s\n", configPath)
	}

	// Check if rootfs exists
	if _, err := os.Stat(rootfs); os.IsNotExist(err) {
		msg := fmt.Sprintf("Rootfs not found at %s, skipping strace injection", rootfs)
		logger.Debug(msg)
		if logFile != nil {
			fmt.Fprintf(logFile, "WARNING: %s\n", msg)
		}
		return nil
	}

	// Step 1: Inject strace binary into container
	if logFile != nil {
		fmt.Fprintf(logFile, "Step 1: Injecting strace...\n")
	}
	if err := injectStrace(rootfs); err != nil {
		msg := fmt.Sprintf("Failed to inject strace: %v", err)
		logger.Warning(msg)
		if logFile != nil {
			fmt.Fprintf(logFile, "WARNING: %s\n", msg)
		}
		// Continue anyway - we'll try to use strace if it's already there
	} else {
		logger.Info("Successfully injected strace into %s", rootfs)
		if logFile != nil {
			fmt.Fprintf(logFile, "SUCCESS: Injected strace\n")
			
			// Verify strace was injected
			stracePath := filepath.Join(rootfs, "usr", "local", "bin", "strace")
			if info, err := os.Stat(stracePath); err == nil {
				fmt.Fprintf(logFile, "Verified: strace exists at %s (size: %d bytes, mode: %s)\n", 
					stracePath, info.Size(), info.Mode())
			} else {
				fmt.Fprintf(logFile, "ERROR: strace not found after injection at %s: %v\n", stracePath, err)
			}
		}
	}

	// Step 2: Modify container config to wrap command with strace
	if logFile != nil {
		fmt.Fprintf(logFile, "Step 2: Wrapping command with strace...\n")
	}
	if err := wrapCommandWithStrace(configPath, state.ID, logFile); err != nil {
		msg := fmt.Sprintf("Failed to wrap command with strace: %v", err)
		logger.Warning(msg)
		if logFile != nil {
			fmt.Fprintf(logFile, "ERROR: %s\n", msg)
		}
		return nil // Non-fatal - build can continue without instrumentation
	}
	
	logger.Info("Successfully wrapped command with strace")
	if logFile != nil {
		fmt.Fprintf(logFile, "SUCCESS: Wrapped command\n")
		fmt.Fprintf(logFile, "Prestart hook completed successfully\n")
	}
	logger.Info("Prestart hook completed for container: %s", state.ID)
	return nil
}

// HandlePoststopHook is called by the poststop OCI hook
// It extracts strace logs from the container after it stops
func HandlePoststopHook(outputDir string) error {
	// Always log to file for debugging
	logFile, _ := os.OpenFile("/tmp/smithy-poststop-hook.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if logFile != nil {
		defer logFile.Close()
		fmt.Fprintf(logFile, "\n=== POSTSTOP HOOK CALLED at %s ===\n", time.Now().Format(time.RFC3339))
		fmt.Fprintf(logFile, "OutputDir: %s\n", outputDir)
	}
	
	logger.Info("=== POSTSTOP HOOK CALLED ===")
	
	// Test: Touch a file to prove hook is running
	testFile := "/tmp/hook-poststop-ran.txt"
	if err := os.WriteFile(testFile, []byte("poststop hook executed\n"), 0644); err != nil {
		logger.Warning("Failed to write test file: %v", err)
		if logFile != nil {
			fmt.Fprintf(logFile, "ERROR: Failed to write test file: %v\n", err)
		}
	}
	
	// Read container state from stdin
	state, err := readContainerState()
	if err != nil {
		msg := fmt.Sprintf("Failed to read container state: %v", err)
		logger.Error(msg)
		if logFile != nil {
			fmt.Fprintf(logFile, "ERROR: %s\n", msg)
		}
		return fmt.Errorf("failed to read container state: %v", err)
	}

	if logFile != nil {
		fmt.Fprintf(logFile, "Container ID: %s\n", state.ID)
		fmt.Fprintf(logFile, "Bundle: %s\n", state.Bundle)
		fmt.Fprintf(logFile, "Root: %s\n", state.Root)
	}

	logger.Info("Poststop hook for container: %s", state.ID)
	logger.Info("Output dir: %s", outputDir)

	// Create output directory if it doesn't exist
	if outputDir == "" {
		outputDir = filepath.Join(os.TempDir(), "smithy-strace-logs")
	}
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		logger.Warning("Failed to create output directory: %v", err)
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	// Get paths from container state
	// Use state.Root which is the actual rootfs path
	rootfs := state.Root
	if rootfs == "" {
		// Fallback to old method
		rootfs = filepath.Join(state.Bundle, "rootfs")
	}
	straceLog := filepath.Join(rootfs, "tmp", "strace-run.log")
	markerFile := filepath.Join(rootfs, "tmp", "strace-marker.txt")

	if logFile != nil {
		fmt.Fprintf(logFile, "Looking for strace log at: %s\n", straceLog)
		fmt.Fprintf(logFile, "Looking for marker at: %s\n", markerFile)
		
		// Check if marker exists
		if _, err := os.Stat(markerFile); err == nil {
			fmt.Fprintf(logFile, "SUCCESS: Marker file exists - strace wrapper ran!\n")
		} else {
			fmt.Fprintf(logFile, "WARNING: Marker file missing - strace wrapper may not have run\n")
		}
	}

	// Check if strace log exists
	if _, err := os.Stat(straceLog); os.IsNotExist(err) {
		msg := fmt.Sprintf("No strace log found at %s", straceLog)
		logger.Debug(msg)
		if logFile != nil {
			fmt.Fprintf(logFile, "WARNING: %s\n", msg)
		}
		return nil
	}

	if logFile != nil {
		fmt.Fprintf(logFile, "Found strace log, extracting...\n")
	}

	// Extract log
	destLog := filepath.Join(outputDir, fmt.Sprintf("%s.log", state.ID))
	if logFile != nil {
		fmt.Fprintf(logFile, "Copying to: %s\n", destLog)
	}
	
	if err := copyFile(straceLog, destLog); err != nil {
		msg := fmt.Sprintf("Failed to extract strace log: %v", err)
		logger.Warning(msg)
		if logFile != nil {
			fmt.Fprintf(logFile, "ERROR: %s\n", msg)
		}
		return nil // Non-fatal
	}

	logger.Info("Extracted strace log: %s", destLog)
	if logFile != nil {
		fmt.Fprintf(logFile, "SUCCESS: Extracted strace log\n")
		fmt.Fprintf(logFile, "Poststop hook completed successfully\n")
	}
	return nil
}

// readContainerState reads OCI container state from stdin
func readContainerState() (*ContainerState, error) {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		// Log to file for debugging
		if logFile, _ := os.OpenFile("/tmp/smithy-hook-debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); logFile != nil {
			fmt.Fprintf(logFile, "Failed to read stdin: %v\n", err)
			logFile.Close()
		}
		return nil, fmt.Errorf("failed to read stdin: %v", err)
	}

	// Log what we received
	if logFile, _ := os.OpenFile("/tmp/smithy-hook-debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); logFile != nil {
		fmt.Fprintf(logFile, "Received stdin (%d bytes): %s\n", len(data), string(data))
		logFile.Close()
	}

	var state ContainerState
	if err := json.Unmarshal(data, &state); err != nil {
		// Log parsing error
		if logFile, _ := os.OpenFile("/tmp/smithy-hook-debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); logFile != nil {
			fmt.Fprintf(logFile, "Failed to parse JSON: %v\n", err)
			logFile.Close()
		}
		return nil, fmt.Errorf("failed to parse container state: %v", err)
	}

	return &state, nil
}

// injectStrace copies the static strace binary into the container
func injectStrace(rootfs string) error {
	// Source: strace binary from smithy image
	straceSrc := "/usr/local/bin/strace"

	// Check if source exists
	if _, err := os.Stat(straceSrc); os.IsNotExist(err) {
		return fmt.Errorf("strace not found at %s", straceSrc)
	}

	// Destination: inside container
	straceDest := filepath.Join(rootfs, "usr", "local", "bin", "strace")

	// Create destination directory
	destDir := filepath.Dir(straceDest)
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("failed to create destination directory: %v", err)
	}

	// Copy strace binary
	if err := copyFile(straceSrc, straceDest); err != nil {
		return fmt.Errorf("failed to copy strace: %v", err)
	}

	// Make it executable
	if err := os.Chmod(straceDest, 0755); err != nil {
		return fmt.Errorf("failed to make strace executable: %v", err)
	}

	logger.Debug("Injected strace into container at: %s", straceDest)
	return nil
}

// wrapCommandWithStrace modifies config.json to wrap the command with strace
func wrapCommandWithStrace(configPath, containerID string, logFile *os.File) error {
	// Read config.json
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config.json: %v", err)
	}

	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse config.json: %v", err)
	}

	// Get process.args
	process, ok := config["process"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("config.json missing process section")
	}

	argsInterface, ok := process["args"]
	if !ok {
		return fmt.Errorf("config.json missing process.args")
	}

	args, ok := argsInterface.([]interface{})
	if !ok {
		return fmt.Errorf("process.args is not an array")
	}

	if logFile != nil {
		fmt.Fprintf(logFile, "Original command args: %v\n", args)
	}

	// Check if already wrapped with strace
	if len(args) > 0 {
		if firstArg, ok := args[0].(string); ok && firstArg == "/bin/sh" {
			if len(args) > 2 {
				if secondArg, ok := args[1].(string); ok && secondArg == "-c" {
					if thirdArg, ok := args[2].(string); ok && strings.Contains(thirdArg, "strace") {
						logger.Debug("Command already wrapped with strace, skipping")
						if logFile != nil {
							fmt.Fprintf(logFile, "Command already wrapped, skipping\n")
						}
						return nil
					}
				}
			}
		}
	}

	// Build the strace wrapper script
	// The original args are like: ["/bin/sh", "-c", "apk add ..."]
	// We need to reconstruct and execute them properly
	var originalCmd string
	if len(args) == 3 {
		// Typical case: ["/bin/sh", "-c", "command"]
		if shell, ok := args[0].(string); ok && shell == "/bin/sh" {
			if flag, ok := args[1].(string); ok && flag == "-c" {
				if cmd, ok := args[2].(string); ok {
					originalCmd = cmd
				}
			}
		}
	}
	
	if originalCmd == "" {
		// Fallback: just convert args to string
		strArgs := make([]string, len(args))
		for i, arg := range args {
			strArgs[i] = fmt.Sprintf("%v", arg)
		}
		originalCmd = strings.Join(strArgs, " ")
	}

	if logFile != nil {
		fmt.Fprintf(logFile, "Extracted original command: %s\n", originalCmd)
	}

	// Wrap with strace - use a simpler approach
	wrappedScript := fmt.Sprintf(
		"touch /tmp/strace-marker.txt && /usr/local/bin/strace -f -e trace=network -e signal=none -qq -o /tmp/strace-run.log /bin/sh -c '%s'",
		strings.ReplaceAll(originalCmd, "'", "'\\''"), // Escape single quotes
	)
	
	newArgs := []interface{}{
		"/bin/sh",
		"-c",
		wrappedScript,
	}

	if logFile != nil {
		fmt.Fprintf(logFile, "New wrapped command args: %v\n", newArgs)
	}

	process["args"] = newArgs

	// Write back modified config
	modifiedData, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal modified config: %v", err)
	}

	if err := os.WriteFile(configPath, modifiedData, 0644); err != nil {
		return fmt.Errorf("failed to write modified config: %v", err)
	}

	logger.Debug("Wrapped command with strace for container: %s", containerID)
	return nil
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	if _, err := io.Copy(destFile, sourceFile); err != nil {
		return err
	}

	// Copy permissions
	srcInfo, err := os.Stat(src)
	if err != nil {
		return err
	}

	return os.Chmod(dst, srcInfo.Mode())
}

// ParseStraceLogs parses all strace logs and extracts network dependencies
func ParseStraceLogs(outputDir string) ([]NetworkDependency, error) {
	if outputDir == "" {
		outputDir = filepath.Join(os.TempDir(), "smithy-strace-logs")
	}

	// Find all log files
	files, err := filepath.Glob(filepath.Join(outputDir, "*.log"))
	if err != nil {
		return nil, fmt.Errorf("failed to find log files: %v", err)
	}

	if len(files) == 0 {
		logger.Warning("No strace logs found in %s", outputDir)
		return []NetworkDependency{}, nil
	}

	logger.Info("Found %d strace log file(s)", len(files))

	var allDeps []NetworkDependency

	for _, file := range files {
		deps, err := parseStraceLog(file)
		if err != nil {
			logger.Warning("Failed to parse %s: %v", file, err)
			continue
		}
		allDeps = append(allDeps, deps...)
	}

	return allDeps, nil
}

// NetworkDependency represents a network dependency discovered during build
type NetworkDependency struct {
	IP       string
	Port     int
	Hostname string
	Source   string // Which log file
}

// parseStraceLog parses a single strace log file
func parseStraceLog(logPath string) ([]NetworkDependency, error) {
	// Use grep to extract connect calls
	cmd := exec.Command("grep", "-oP", "sin_addr=inet_addr\\(\"\\K[^\"]+", logPath)
	output, err := cmd.Output()
	if err != nil {
		// No matches is OK
		return []NetworkDependency{}, nil
	}

	var deps []NetworkDependency
	
	// For now, just collect unique IPs
	// TODO: Parse ports, resolve hostnames, etc.
	_ = string(output) // Suppress unused warning for now
	
	logger.Debug("Parsed %s: found network activity", logPath)
	
	return deps, nil
}