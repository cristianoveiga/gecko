package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	"github.com/openshift-online/gecko/platform-api/pkg/featureflags"
)

func TestValidatePublicAuthAddress(t *testing.T) {
	tests := []struct {
		name          string
		enablePublic  bool
		address       string
		publicAddress string
		devAuth       bool
		disableAuth   bool
		wantErr       bool
	}{
		{
			name:         "auth enabled does not require loopback",
			enablePublic: true,
			address:      "0.0.0.0",
		},
		{
			name:          "dev auth loopback",
			enablePublic:  true,
			publicAddress: "127.0.0.1",
			devAuth:       true,
		},
		{
			name:          "dev auth localhost",
			enablePublic:  true,
			publicAddress: "localhost",
			devAuth:       true,
		},
		{
			name:          "dev auth IPv6 loopback",
			enablePublic:  true,
			publicAddress: "::1",
			devAuth:       true,
		},
		{
			name:          "dev auth non-loopback",
			enablePublic:  true,
			publicAddress: "0.0.0.0",
			devAuth:       true,
			wantErr:       true,
		},
		{
			name:         "dev auth implicit non-loopback",
			enablePublic: true,
			address:      "0.0.0.0",
			devAuth:      true,
			wantErr:      true,
		},
		{
			name:          "disabled auth non-loopback",
			enablePublic:  true,
			publicAddress: "192.0.2.10",
			disableAuth:   true,
			wantErr:       true,
		},
		{
			name:          "public API disabled",
			enablePublic:  false,
			publicAddress: "0.0.0.0",
			devAuth:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePublicAuthAddress(tt.enablePublic, tt.address, tt.publicAddress, tt.devAuth, tt.disableAuth)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validatePublicAuthAddress() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				for _, address := range []string{tt.address, tt.publicAddress} {
					if address != "" && strings.Contains(err.Error(), address) {
						t.Errorf("validation error exposes bind address %q: %v", address, err)
					}
				}
			}
		})
	}
}

func TestConditionalAuthorizationMiddleware(t *testing.T) {
	tests := []struct {
		name       string
		defaultVar string
		wantCode   int
	}{
		{name: "enforced", defaultVar: "enabled", wantCode: http.StatusForbidden},
		{name: "disabled", defaultVar: "disabled", wantCode: http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "flags.json")
			contents := []byte(`{
  "$schema": "https://flagd.dev/schema/v0/flags.json",
  "flags": {
    "gecko.public-api.authorization.enabled": {
      "state": "ENABLED",
      "variants": {
        "enabled": true,
        "disabled": false
      },
      "defaultVariant": "` + tt.defaultVar + `"
    }
  }
}`)
			if err := os.WriteFile(path, contents, 0o600); err != nil {
				t.Fatalf("write flags: %v", err)
			}
			t.Setenv("FLAGD_OFFLINE_FLAG_SOURCE_PATH", path)

			evaluator, err := featureflags.NewFromEnvironment()
			if err != nil {
				t.Fatalf("initialize feature flags: %v", err)
			}
			defer evaluator.Shutdown()

			authorization := func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusForbidden)
				})
			}
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})
			handler := conditionalAuthorizationMiddleware(evaluator, authorization, logr.Discard())(next)

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/apis/gcp.managed.openshift.io/v1/namespaces/test/clusters", nil))
			if recorder.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d", recorder.Code, tt.wantCode)
			}
		})
	}
}
