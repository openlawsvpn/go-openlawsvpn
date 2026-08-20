package main

import (
	"strings"
	"testing"
)

func TestAuthLogDoesNotContainCredentials(t *testing.T) {
	const canary = "CANARY_SAML_ASSERTION_MUST_NOT_BE_LOGGED"
	info := buildAuthInfo("options", "N/A", "CRV1::state::"+canary, "peer-info", 512)
	got := info.safeLog()
	if strings.Contains(got, canary) || strings.Contains(got, "CRV1::") || strings.Contains(got, "state") {
		t.Fatalf("safe auth log disclosed credential material: %s", got)
	}
	if !strings.Contains(got, `"credential_kind":"crv1"`) {
		t.Fatalf("safe auth log omitted credential classification: %s", got)
	}
}
