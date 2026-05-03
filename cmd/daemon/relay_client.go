// SPDX-License-Identifier: LGPL-2.1-or-later

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	relayDefaultBase = "https://api.relay.openlawsvpn.com/api/v1"
	relayHTTPTimeout = 15 * time.Second
)

var relayHTTP = &http.Client{Timeout: relayHTTPTimeout}

// relayConnect calls POST /connect and returns the session_id.
func relayConnect(baseURL, orgToken, agentID string) (string, error) {
	body, _ := json.Marshal(map[string]string{
		"agent_id": agentID,
	})
	resp, err := relayPost(baseURL+"/connect", orgToken, body)
	if err != nil {
		return "", err
	}
	sid, ok := resp["session_id"].(string)
	if !ok || sid == "" {
		return "", fmt.Errorf("relay: connect: missing session_id in response")
	}
	return sid, nil
}

// relayExecute calls POST /session/:id/execute to deliver Phase 2 credentials.
func relayExecute(baseURL, orgToken, sessionID, ovpnConfig, stateID, samlResponse, remoteIP string) error {
	body, _ := json.Marshal(map[string]string{
		"ovpn_config":   ovpnConfig,
		"state_id":      stateID,
		"saml_response": samlResponse,
		"remote_ip":     remoteIP,
	})
	_, err := relayPost(fmt.Sprintf("%s/session/%s/execute", baseURL, sessionID), orgToken, body)
	return err
}

// relayRelease calls DELETE /session/:id/release to push a disconnect to the agent.
func relayRelease(baseURL, orgToken, sessionID string) error {
	req, err := http.NewRequest(http.MethodDelete,
		fmt.Sprintf("%s/session/%s/release", baseURL, sessionID),
		bytes.NewReader([]byte("{}")))
	if err != nil {
		return fmt.Errorf("relay: build release request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+orgToken)
	res, err := relayHTTP.Do(req)
	if err != nil {
		return fmt.Errorf("relay: DELETE release: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		raw, _ := io.ReadAll(res.Body)
		return fmt.Errorf("relay: release HTTP %d — %s", res.StatusCode, string(raw))
	}
	return nil
}

// relayListAgents calls GET /agents and returns the raw JSON body.
func relayListAgents(baseURL, orgToken string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, baseURL+"/agents", nil)
	if err != nil {
		return nil, fmt.Errorf("relay: build agents request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+orgToken)
	res, err := relayHTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("relay: GET agents: %w", err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("relay: GET agents HTTP %d — %s", res.StatusCode, string(raw))
	}
	return raw, nil
}

func relayPost(url, orgToken string, body []byte) (map[string]interface{}, error) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("relay: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+orgToken)

	res, err := relayHTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("relay: POST %s: %w", url, err)
	}
	defer res.Body.Close()

	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("relay: POST %s: HTTP %d — %s", url, res.StatusCode, string(raw))
	}

	var out map[string]interface{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	return out, nil
}
