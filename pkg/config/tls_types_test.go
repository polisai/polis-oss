package config

import (
	"testing"
)

func TestParseTLSVersion(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected TLSVersion
		wantErr  bool
	}{
		{
			name:     "empty string defaults to TLS 1.2",
			input:    "",
			expected: TLSVersion12,
			wantErr:  false,
		},
		{
			name:     "valid TLS 1.2",
			input:    "1.2",
			expected: TLSVersion12,
			wantErr:  false,
		},
		{
			name:     "valid TLS 1.3",
			input:    "1.3",
			expected: TLSVersion13,
			wantErr:  false,
		},
		{
			name:     "invalid version",
			input:    "2.0",
			expected: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseTLSVersion(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseTLSVersion() expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("ParseTLSVersion() unexpected error: %v", err)
				}
				if result != tt.expected {
					t.Errorf("ParseTLSVersion() = %v, want %v", result, tt.expected)
				}
			}
		})
	}
}

func TestTLSConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  TLSConfig
		wantErr bool
	}{
		{
			name: "disabled TLS is valid",
			config: TLSConfig{
				Enabled: false,
			},
			wantErr: false,
		},
		{
			name: "enabled TLS with cert and key is valid",
			config: TLSConfig{
				Enabled:  true,
				CertFile: "/path/to/cert.pem",
				KeyFile:  "/path/to/key.pem",
			},
			wantErr: false,
		},
		{
			name: "enabled TLS without cert file is invalid",
			config: TLSConfig{
				Enabled: true,
				KeyFile: "/path/to/key.pem",
			},
			wantErr: true,
		},
		{
			name: "enabled TLS without key file is invalid",
			config: TLSConfig{
				Enabled:  true,
				CertFile: "/path/to/cert.pem",
			},
			wantErr: true,
		},
		{
			name: "invalid min version",
			config: TLSConfig{
				Enabled:    true,
				CertFile:   "/path/to/cert.pem",
				KeyFile:    "/path/to/key.pem",
				MinVersion: "invalid",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				if err == nil {
					t.Errorf("TLSConfig.Validate() expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("TLSConfig.Validate() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestListenParamConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  ListenParamConfig
		wantErr bool
	}{
		{
			name: "valid HTTP config",
			config: ListenParamConfig{
				Address:  ":8080",
				Protocol: "http",
			},
			wantErr: false,
		},
		{
			name: "valid HTTPS config with TLS",
			config: ListenParamConfig{
				Address:  ":8443",
				Protocol: "https",
				TLS: &TLSConfig{
					Enabled:  true,
					CertFile: "/path/to/cert.pem",
					KeyFile:  "/path/to/key.pem",
				},
			},
			wantErr: false,
		},
		{
			name: "HTTPS without TLS config is invalid",
			config: ListenParamConfig{
				Address:  ":8443",
				Protocol: "https",
			},
			wantErr: true,
		},
		{
			name: "empty address is invalid",
			config: ListenParamConfig{
				Protocol: "http",
			},
			wantErr: true,
		},
		{
			name: "invalid protocol",
			config: ListenParamConfig{
				Address:  ":8080",
				Protocol: "invalid",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				if err == nil {
					t.Errorf("ListenParamConfig.Validate() expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("ListenParamConfig.Validate() unexpected error: %v", err)
				}
			}
		})
	}
}
