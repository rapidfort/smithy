package build

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rapidfort/smithy/pkg/logger"
)

// OCIHook represents an OCI hook configuration (version 1.0.0)
type OCIHook struct {
	Version string   `json:"version"`
	Hook    HookSpec `json:"hook"`
	When    WhenSpec `json:"when"`
	Stages  []string `json:"stages"`
}

// HookSpec defines the hook executable
type HookSpec struct {
	Path string   `json:"path"`
	Args []string `json:"args,omitempty"`
	Env  []string `json:"env,omitempty"`
}

// WhenSpec defines when the hook should run
type WhenSpec struct {
	Always       bool     `json:"always,omitempty"`
	Commands     []string `json:"commands,omitempty"`
	Annotations  []string `json:"annotations,omitempty"`
	HasBindMounts bool    `json:"hasBindMounts,omitempty"`
}

// HooksConfig holds configuration for instrumentation hooks
type HooksConfig struct {
	Enabled    bool
	HooksDir   string
	OutputDir  string
	Executable string // Path to smithy executable for hooks
}

// SetupInstrumentationHooks creates OCI hooks for strace instrumentation
func SetupInstrumentationHooks(config HooksConfig) (string, error) {
	if !config.Enabled {
		return "", nil
	}

	// Create hooks directory
	hooksDir := config.HooksDir
	if hooksDir == "" {
		hooksDir = "/tmp/smithy-hooks"
	}

	// Remove old hooks if they exist
	os.RemoveAll(hooksDir)

	if err := os.MkdirAll(hooksDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create hooks directory: %v", err)
	}

	logger.Info("Created hooks directory: %s", hooksDir)
	
	// Verify directory exists
	if _, err := os.Stat(hooksDir); os.IsNotExist(err) {
		return "", fmt.Errorf("hooks directory vanished after creation: %s", hooksDir)
	}

	// Get smithy executable path
	executable := config.Executable
	if executable == "" {
		// Try to find smithy in PATH or use self
		var err error
		executable, err = os.Executable()
		if err != nil {
			return "", fmt.Errorf("failed to determine smithy executable: %v", err)
		}
	}

	// Create prestart hook for strace injection
	if err := createPrestartHook(hooksDir, executable, config.OutputDir); err != nil {
		return "", fmt.Errorf("failed to create prestart hook: %v", err)
	}
	logger.Info("Created prestart hook")

	// Create poststop hook for log extraction
	if err := createPoststopHook(hooksDir, executable, config.OutputDir); err != nil {
		return "", fmt.Errorf("failed to create poststop hook: %v", err)
	}
	logger.Info("Created poststop hook")

	// Verify hook files exist
	files, _ := os.ReadDir(hooksDir)
	logger.Info("Hooks directory contains %d files", len(files))
	for _, f := range files {
		logger.Debug("  - %s", f.Name())
	}

	logger.Info("Instrumentation hooks configured at: %s", hooksDir)
	return hooksDir, nil
}

// createPrestartHook creates the prestart hook that injects strace
func createPrestartHook(hooksDir, executable, outputDir string) error {
	hook := OCIHook{
		Version: "1.0.0",
		Hook: HookSpec{
			Path: executable,
			Args: []string{
				executable,
				"__internal_hook_prestart",
				"--output-dir", outputDir,
			},
		},
		When: WhenSpec{
			Always: true,
		},
		Stages: []string{"createRuntime"}, // Changed from prestart to createRuntime
	}

	data, err := json.MarshalIndent(hook, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal prestart hook: %v", err)
	}

	hookPath := filepath.Join(hooksDir, "00-strace-injection.json")
	if err := os.WriteFile(hookPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write prestart hook: %v", err)
	}

	logger.Debug("Created prestart hook: %s", hookPath)
	return nil
}

// createPoststopHook creates the poststop hook that extracts logs
func createPoststopHook(hooksDir, executable, outputDir string) error {
	hook := OCIHook{
		Version: "1.0.0",
		Hook: HookSpec{
			Path: executable,
			Args: []string{
				executable,
				"__internal_hook_poststop",
				"--output-dir", outputDir,
			},
		},
		When: WhenSpec{
			Always: true,
		},
		Stages: []string{"poststop"},
	}

	data, err := json.MarshalIndent(hook, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal poststop hook: %v", err)
	}

	hookPath := filepath.Join(hooksDir, "99-strace-extraction.json")
	if err := os.WriteFile(hookPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write poststop hook: %v", err)
	}

	logger.Debug("Created poststop hook: %s", hookPath)
	return nil
}

// CleanupHooks removes temporary hooks directory
func CleanupHooks(hooksDir string) error {
	if hooksDir == "" {
		return nil
	}

	if err := os.RemoveAll(hooksDir); err != nil {
		logger.Warning("Failed to cleanup hooks directory %s: %v", hooksDir, err)
		return err
	}

	logger.Debug("Cleaned up hooks directory: %s", hooksDir)
	return nil
}