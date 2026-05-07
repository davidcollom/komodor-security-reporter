package komodor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestValidateAPIKey(t *testing.T) {
	tests := []struct {
		name         string
		statusCode   int
		responseBody string
		wantError    string
		wantAPIKey   string
	}{
		{
			name:         "valid api key",
			statusCode:   http.StatusOK,
			responseBody: `{"valid": true}`,
			wantAPIKey:   "test-key",
		},
		{
			name:         "invalid api key",
			statusCode:   http.StatusForbidden,
			responseBody: `{"Status": "Forbidden"}`,
			wantError:    "invalid Komodor API key",
			wantAPIKey:   "test-key",
		},
		{
			name:         "unexpected successful response",
			statusCode:   http.StatusOK,
			responseBody: `{"valid": false}`,
			wantError:    "unexpected response",
			wantAPIKey:   "test-key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, http.MethodGet, r.Method)
				require.Equal(t, tt.wantAPIKey, r.Header.Get("X-API-KEY"))
				w.WriteHeader(tt.statusCode)
				_, err := w.Write([]byte(tt.responseBody))
				require.NoError(t, err)
			}))
			defer server.Close()

			client := NewClient("https://app.komodor.io", "test-key", logrus.New())
			client.validateURL = server.URL

			err := client.ValidateAPIKey(context.Background())

			if tt.wantError == "" {
				require.NoError(t, err)
				return
			}

			require.Error(t, err)
			require.Contains(t, err.Error(), tt.wantError)
		})
	}
}

func TestPublishEventRejectsNilEvent(t *testing.T) {
	client := NewClient("https://api.komodor.com", "test-key", logrus.New())

	err := client.PublishEvent(context.Background(), nil)

	require.Error(t, err)
	require.Contains(t, err.Error(), "event is required")
}

func TestPublishEventSendsSchemaAlignedPayload(t *testing.T) {
	type postedEvent struct {
		EventType string                 `json:"eventType"`
		Summary   string                 `json:"summary"`
		Severity  string                 `json:"severity"`
		Scope     map[string]interface{} `json:"scope"`
		Details   map[string]interface{} `json:"details"`
	}

	var got postedEvent

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "test-key", r.Header.Get("X-API-KEY"))

		defer r.Body.Close()

		err := json.NewDecoder(r.Body).Decode(&got)
		require.NoError(t, err)

		w.WriteHeader(http.StatusCreated)
		_, err = w.Write([]byte(`{"message":"ok"}`))
		require.NoError(t, err)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-key", logrus.New())
	err := client.PublishEvent(context.Background(), &Event{
		EventType: "vulnerability-scan",
		Summary:   "3 findings in payments/api",
		Severity:  "warning",
		Scope: Scope{
			Clusters:      []string{"prod-eks-01"},
			Namespaces:    []string{"payments"},
			ServicesNames: []string{"api"},
		},
		Details: map[string]interface{}{
			"scanner": "trivy",
		},
	})
	require.NoError(t, err)

	require.Equal(t, "vulnerability-scan", got.EventType)
	require.Equal(t, "3 findings in payments/api", got.Summary)
	require.Equal(t, "warning", got.Severity)
	require.NotNil(t, got.Scope)
	require.NotNil(t, got.Details)
}
