package komodor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// Client provides Komodor API interactions.
type Client struct {
	baseURL     string
	apiKey      string
	validateURL string
	httpClient  *http.Client
	log         logrus.FieldLogger
}

const defaultAPIKeyValidationURL = "https://api.komodor.com/api/v2/apikey/validate" // #nosec G101 - This is a fixed URL for API key validation, not user input.

// NewClient creates a new Komodor API client.
func NewClient(baseURL, apiKey string, log logrus.FieldLogger) *Client {
	return &Client{
		baseURL:     baseURL,
		apiKey:      apiKey,
		validateURL: defaultAPIKeyValidationURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		log: log,
	}
}

type apiKeyValidationResponse struct {
	Valid  bool   `json:"valid"`
	Status string `json:"Status"`
}

func (c *Client) setAuthHeaders(req *http.Request) {
	req.Header.Set("X-API-KEY", c.apiKey)
	// req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.apiKey))
}

// ValidateAPIKey verifies that the configured API key is accepted by Komodor.
func (c *Client) ValidateAPIKey(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.validateURL, nil)
	if err != nil {
		return fmt.Errorf("create validation request: %w", err)
	}

	c.setAuthHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("validate api key: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	body, validationResp, err := parseAPIKeyValidationResponse(resp.Body)
	if err != nil {
		return err
	}

	return evaluateAPIKeyValidation(resp.StatusCode, body, validationResp)
}

func parseAPIKeyValidationResponse(bodyReader io.Reader) ([]byte, apiKeyValidationResponse, error) {
	body, err := io.ReadAll(bodyReader)
	if err != nil {
		return nil, apiKeyValidationResponse{}, fmt.Errorf("read validation response: %w", err)
	}

	var validationResp apiKeyValidationResponse
	if len(body) == 0 {
		return body, validationResp, nil
	}

	if err := json.Unmarshal(body, &validationResp); err != nil {
		return nil, apiKeyValidationResponse{}, fmt.Errorf("decode validation response: %w", err)
	}

	return body, validationResp, nil
}

func evaluateAPIKeyValidation(statusCode int, body []byte, validationResp apiKeyValidationResponse) error {
	if statusCode == http.StatusForbidden || strings.EqualFold(validationResp.Status, "Forbidden") {
		return fmt.Errorf("invalid Komodor API key")
	}

	if statusCode < 200 || statusCode >= 300 {
		return fmt.Errorf("validate api key: status %d: %s", statusCode, string(body))
	}

	if !validationResp.Valid {
		return fmt.Errorf("validate api key: unexpected response: %s", string(body))
	}

	return nil
}

// Event represents a Komodor event.
type Event struct {
	EventType string                 `json:"eventType"`
	Summary   string                 `json:"summary"`
	Severity  string                 `json:"severity,omitempty"`
	Scope     Scope                  `json:"scope,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// Scope represents the event correlation scope.
type Scope struct {
	Clusters      []string `json:"clusters,omitempty"`
	Namespaces    []string `json:"namespaces,omitempty"`
	ServicesNames []string `json:"servicesNames,omitempty"`
}

// PublishEvent publishes an event to Komodor.
func (c *Client) PublishEvent(ctx context.Context, event *Event) error {
	if event == nil {
		return fmt.Errorf("publish event: event is required")
	}

	body, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}

	eventsURL, err := url.JoinPath(c.baseURL, "/mgmt/v1/events")
	if err != nil {
		return fmt.Errorf("build events url: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, eventsURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	c.setAuthHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("publish event: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("publish event: status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}
