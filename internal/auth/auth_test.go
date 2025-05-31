package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		header  string
		wantKey string
		wantErr error
	}{
		{
			name:    "no Authorization header",
			header:  "",
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:    "malformed header: wrong prefix",
			header:  "Bearer sometoken",
			wantKey: "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name:    "malformed header: only prefix",
			header:  "ApiKey",
			wantKey: "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name:    "valid header: single token",
			header:  "ApiKey myapikey123",
			wantKey: "myapikey123",
			wantErr: nil,
		},
		{
			name:    "valid header: extra segments",
			header:  "ApiKey mykey extra junk",
			wantKey: "mykey",
			wantErr: nil,
		},
		{
			name:    "prefix with space but no key",
			header:  "ApiKey ",
			wantKey: "",
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			if tt.header != "" {
				headers.Set("Authorization", tt.header)
			}

			gotKey, err := GetAPIKey(headers)

			// 1) Check returned key
			if gotKey != tt.wantKey {
				t.Errorf("GetAPIKey() returned key %q, want %q", gotKey, tt.wantKey)
			}

			// 2) Check error presence vs. expectation
			if (err == nil) != (tt.wantErr == nil) {
				t.Fatalf("GetAPIKey() error = %v, wantErr = %v", err, tt.wantErr)
			}

			// 3) If an error was expected, compare error messages
			if tt.wantErr != nil && err.Error() != tt.wantErr.Error() {
				t.Errorf("GetAPIKey() error = %q, want %q", err.Error(), tt.wantErr.Error())
			}
		})
	}
}
