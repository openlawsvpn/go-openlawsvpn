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
	relayDefaultBase = "https://relay.openlawsvpn.com/api/v1"
	relayHTTPTimeout = 15 * time.Second
)

var relayHTTP = &http.Client{Timeout: relayHTTPTimeout}

// relayConnect calls POST /connect and returns the session_id.
func relayConnect(baseURL, orgToken, agentID string) (string, error) {
	body, _ := json.Marshal(map[string]string{
		"token":    orgToken,
		"agent_id": agentID,
	})
	resp, err := relayPost(baseURL+"/connect", body)
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
func relayExecute(baseURL, sessionID, ovpnConfig, stateID, samlResponse, remoteIP string) error {
	body, _ := json.Marshal(map[string]string{
		"ovpn_config":   ovpnConfig,
		"state_id":      stateID,
		"saml_response": samlResponse,
		"remote_ip":     remoteIP,
	})
	_, err := relayPost(fmt.Sprintf("%s/session/%s/execute", baseURL, sessionID), body)
	return err
}

func relayPost(url string, body []byte) (map[string]interface{}, error) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("relay: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

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
