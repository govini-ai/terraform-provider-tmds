package provider

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client is a minimal Deep Security Manager REST API client.
// Ported from the read-only Python prototype (tmds-policy/sync.py).
type Client struct {
	BaseURL    string
	apiKey     string
	httpClient *http.Client
}

func NewClient(baseURL, apiKey string, insecure bool) *Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure}, //nolint:gosec // opt-in for self-signed DSM cert
	}
	return &Client{
		BaseURL:    strings.TrimRight(baseURL, "/"),
		apiKey:     apiKey,
		httpClient: &http.Client{Timeout: 30 * time.Second, Transport: tr},
	}
}

// ModuleState is the per-module on/off/inherited state.
type ModuleState struct {
	State string `json:"state,omitempty"`
}

// SettingValue is the DSM's wrapper for a single policy setting value.
type SettingValue struct {
	Value string `json:"value"`
}

// Policy mirrors the subset of the DSM Policy object we manage. We model only
// what we assign; everything else inherits from the parent policy.
type Policy struct {
	ID                  int64        `json:"ID,omitempty"`
	Name                string       `json:"name"`
	Description         string       `json:"description,omitempty"`
	ParentID            int64        `json:"parentID,omitempty"`
	AntiMalware         *ModuleState `json:"antiMalware,omitempty"`
	WebReputation       *ModuleState `json:"webReputation,omitempty"`
	Firewall            *ModuleState `json:"firewall,omitempty"`
	IntrusionPrevention *ModuleState `json:"intrusionPrevention,omitempty"`
	IntegrityMonitoring *ModuleState `json:"integrityMonitoring,omitempty"`
	LogInspection       *ModuleState `json:"logInspection,omitempty"`
	// Only the settings we manage are sent; the DSM returns the full set on read.
	PolicySettings map[string]SettingValue `json:"policySettings,omitempty"`
}

// Policy setting keys we manage as typed attributes.
const settingNetworkEngineMode = "firewallSettingNetworkEngineMode"

func (c *Client) do(method, path string, body interface{}) ([]byte, int, error) {
	var buf io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		buf = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, c.BaseURL+"/api"+path, buf)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("api-secret-key", c.apiKey)
	req.Header.Set("api-version", "v1")
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return data, resp.StatusCode, fmt.Errorf("DSM API %s %s: %d %s", method, path, resp.StatusCode, string(data))
	}
	return data, resp.StatusCode, nil
}

func (c *Client) CreatePolicy(p *Policy) (*Policy, error) {
	data, _, err := c.do(http.MethodPost, "/policies", p)
	if err != nil {
		return nil, err
	}
	var out Policy
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetPolicy returns the policy, or (nil, nil) if it no longer exists (404).
func (c *Client) GetPolicy(id int64) (*Policy, error) {
	data, status, err := c.do(http.MethodGet, fmt.Sprintf("/policies/%d", id), nil)
	if status == http.StatusNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out Policy
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdatePolicy modifies an existing policy. DSM uses POST (not PUT) for modify.
func (c *Client) UpdatePolicy(id int64, p *Policy) (*Policy, error) {
	data, _, err := c.do(http.MethodPost, fmt.Sprintf("/policies/%d", id), p)
	if err != nil {
		return nil, err
	}
	var out Policy
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) DeletePolicy(id int64) error {
	_, _, err := c.do(http.MethodDelete, fmt.Sprintf("/policies/%d", id), nil)
	return err
}

// policySearch mirrors the DSM search request/response for policies.
type policySearch struct {
	MaxItems       int              `json:"maxItems,omitempty"`
	SearchCriteria []searchCriteria `json:"searchCriteria"`
}

// In the DSM API, stringTest is the operator (a scalar enum) and the value
// goes in stringValue — not a nested object.
type searchCriteria struct {
	FieldName   string `json:"fieldName"`
	StringTest  string `json:"stringTest"`
	StringValue string `json:"stringValue"`
}

type policyListResponse struct {
	Policies []Policy `json:"policies"`
}

// SearchPolicyByName resolves a policy by its name to that manager's local
// object. Names are stable across managers; IDs are not. Returns (nil, nil)
// when no policy matches.
func (c *Client) SearchPolicyByName(name string) (*Policy, error) {
	body := policySearch{
		MaxItems: 1,
		SearchCriteria: []searchCriteria{{
			FieldName:   "name",
			StringTest:  "equal",
			StringValue: name,
		}},
	}
	data, _, err := c.do(http.MethodPost, "/policies/search", body)
	if err != nil {
		return nil, err
	}
	var out policyListResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	if len(out.Policies) == 0 {
		return nil, nil
	}
	return &out.Policies[0], nil
}
