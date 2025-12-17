package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExpandEnvVars(t *testing.T) {
	// Set up test environment variables
	os.Setenv("TEST_VAR", "test_value")
	os.Setenv("ANOTHER_VAR", "another_value")
	defer func() {
		os.Unsetenv("TEST_VAR")
		os.Unsetenv("ANOTHER_VAR")
	}()

	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "no env vars",
			input:    []string{"npx", "-y", "some-package"},
			expected: []string{"npx", "-y", "some-package"},
		},
		{
			name:     "single env var with dollar sign",
			input:    []string{"echo", "$TEST_VAR"},
			expected: []string{"echo", "test_value"},
		},
		{
			name:     "single env var with braces",
			input:    []string{"echo", "${TEST_VAR}"},
			expected: []string{"echo", "test_value"},
		},
		{
			name:     "multiple env vars",
			input:    []string{"cmd", "$TEST_VAR", "${ANOTHER_VAR}"},
			expected: []string{"cmd", "test_value", "another_value"},
		},
		{
			name:     "env var in middle of string",
			input:    []string{"path=/home/$TEST_VAR/data"},
			expected: []string{"path=/home/test_value/data"},
		},
		{
			name:     "undefined env var expands to empty",
			input:    []string{"echo", "$UNDEFINED_VAR"},
			expected: []string{"echo", ""},
		},
		{
			name:     "empty input",
			input:    []string{},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := expandEnvVars(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseCLIConfig(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		flags       map[string]string
		cmdArgs     []string
		expectError bool
		expected    *CLIConfig
	}{
		{
			name:    "default values",
			args:    []string{},
			flags:   map[string]string{},
			cmdArgs: []string{},
			expected: &CLIConfig{
				Port:     defaultPort,
				Config:   "",
				LogLevel: defaultLogLevel,
				Command:  []string{},
			},
		},
		{
			name: "custom port",
			args: []string{},
			flags: map[string]string{
				"port": "9000",
			},
			cmdArgs: []string{},
			expected: &CLIConfig{
				Port:     "9000",
				Config:   "",
				LogLevel: defaultLogLevel,
				Command:  []string{},
			},
		},
		{
			name: "all flags set",
			args: []string{},
			flags: map[string]string{
				"port":      "8080",
				"config":    "/path/to/config.yaml",
				"log-level": "debug",
			},
			cmdArgs: []string{"npx", "-y", "some-package"},
			expected: &CLIConfig{
				Port:     "8080",
				Config:   "/path/to/config.yaml",
				LogLevel: "debug",
				Command:  []string{"npx", "-y", "some-package"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newRootCmd()

			// Set flags
			for key, value := range tt.flags {
				err := cmd.Flags().Set(key, value)
				require.NoError(t, err)
			}

			config, err := parseCLIConfig(cmd, tt.cmdArgs)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected.Port, config.Port)
			assert.Equal(t, tt.expected.Config, config.Config)
			assert.Equal(t, tt.expected.LogLevel, config.LogLevel)
			assert.Equal(t, tt.expected.Command, config.Command)
		})
	}
}

func TestBuildBridgeConfig(t *testing.T) {
	tests := []struct {
		name           string
		cliConfig      *CLIConfig
		expectError    bool
		expectedAddr   string
		expectedCmd    []string
	}{
		{
			name: "basic config from CLI",
			cliConfig: &CLIConfig{
				Port:     "8090",
				Config:   "",
				LogLevel: "info",
				Command:  []string{"npx", "-y", "some-package"},
			},
			expectedAddr: ":8090",
			expectedCmd:  []string{"npx", "-y", "some-package"},
		},
		{
			name: "custom port",
			cliConfig: &CLIConfig{
				Port:     "9000",
				Config:   "",
				LogLevel: "info",
				Command:  []string{"echo", "hello"},
			},
			expectedAddr: ":9000",
			expectedCmd:  []string{"echo", "hello"},
		},
		{
			name: "env var expansion in command",
			cliConfig: &CLIConfig{
				Port:     "8090",
				Config:   "",
				LogLevel: "info",
				Command:  []string{"echo", "$HOME"},
			},
			expectedAddr: ":8090",
			// HOME should be expanded
		},
		{
			name: "non-existent config file",
			cliConfig: &CLIConfig{
				Port:     "8090",
				Config:   "/non/existent/path.yaml",
				LogLevel: "info",
				Command:  []string{"echo"},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := buildBridgeConfig(tt.cliConfig)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expectedAddr, config.ListenAddr)

			if tt.name == "env var expansion in command" {
				// Just verify the command was processed
				assert.Len(t, config.Command, 2)
				assert.Equal(t, "echo", config.Command[0])
				// HOME should be expanded to something (not $HOME)
				assert.NotEqual(t, "$HOME", config.Command[1])
			} else if tt.expectedCmd != nil {
				assert.Equal(t, tt.expectedCmd, config.Command)
			}
		})
	}
}

func TestNewRootCmd(t *testing.T) {
	cmd := newRootCmd()

	// Verify command structure
	assert.Equal(t, "polis-bridge", cmd.Use)
	assert.NotEmpty(t, cmd.Short)
	assert.NotEmpty(t, cmd.Long)

	// Verify flags exist
	portFlag := cmd.Flags().Lookup("port")
	require.NotNil(t, portFlag)
	assert.Equal(t, "p", portFlag.Shorthand)
	assert.Equal(t, defaultPort, portFlag.DefValue)

	configFlag := cmd.Flags().Lookup("config")
	require.NotNil(t, configFlag)
	assert.Equal(t, "c", configFlag.Shorthand)
	assert.Equal(t, "", configFlag.DefValue)

	logLevelFlag := cmd.Flags().Lookup("log-level")
	require.NotNil(t, logLevelFlag)
	assert.Equal(t, "l", logLevelFlag.Shorthand)
	assert.Equal(t, defaultLogLevel, logLevelFlag.DefValue)
}

func TestCommandSeparatorHandling(t *testing.T) {
	// Test that arguments after -- are correctly passed as command
	cmd := newRootCmd()

	// Simulate parsing with command after --
	// In cobra, args after -- are passed to the Run function
	cmdArgs := []string{"npx", "-y", "@modelcontextprotocol/server-filesystem", "/home/user"}

	config, err := parseCLIConfig(cmd, cmdArgs)
	require.NoError(t, err)

	assert.Equal(t, cmdArgs, config.Command)
	assert.Len(t, config.Command, 4)
	assert.Equal(t, "npx", config.Command[0])
	assert.Equal(t, "-y", config.Command[1])
	assert.Equal(t, "@modelcontextprotocol/server-filesystem", config.Command[2])
	assert.Equal(t, "/home/user", config.Command[3])
}
