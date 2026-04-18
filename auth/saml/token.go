package saml

import (
	"encoding/base64"
	"strings"
	"time"
)

// TokenExpiry parses the NotOnOrAfter timestamp from a base64-encoded SAML
// assertion and returns the expiry time.
//
// Returns zero time if the token cannot be decoded or the attribute is absent
// (caller should treat zero as unknown/infinite).
//
// The SAML assertion is base64-encoded XML. We do a simple string scan for
// NotOnOrAfter= rather than a full XML parse to avoid importing encoding/xml
// and to handle both SubjectConfirmationData and Conditions elements.
// AWS IdPs (Okta, Azure AD, Google Workspace) all use ISO 8601 UTC format:
// "2006-01-02T15:04:05Z" or "2006-01-02T15:04:05.000Z".
func TokenExpiry(base64Token string) time.Time {
	xml, err := base64.StdEncoding.DecodeString(base64Token)
	if err != nil {
		// Try URL-safe variant.
		xml2, err2 := base64.URLEncoding.DecodeString(base64Token)
		if err2 != nil {
			return time.Time{}
		}
		xml = xml2
	}
	return earliestNotOnOrAfter(string(xml))
}

// earliestNotOnOrAfter scans raw SAML XML and returns the earliest
// NotOnOrAfter timestamp found, which is the effective token expiry.
func earliestNotOnOrAfter(xml string) time.Time {
	const attr = `NotOnOrAfter="`
	var earliest time.Time
	rest := xml
	for {
		idx := strings.Index(rest, attr)
		if idx < 0 {
			break
		}
		rest = rest[idx+len(attr):]
		end := strings.IndexByte(rest, '"')
		if end < 0 {
			break
		}
		ts := rest[:end]
		rest = rest[end+1:]

		t := parseSAMLTime(ts)
		if t.IsZero() {
			continue
		}
		if earliest.IsZero() || t.Before(earliest) {
			earliest = t
		}
	}
	return earliest
}

// parseSAMLTime parses ISO 8601 UTC timestamps as used in SAML assertions.
func parseSAMLTime(s string) time.Time {
	formats := []string{
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05.000Z",
		"2006-01-02T15:04:05.0Z",
		"2006-01-02T15:04:05.00Z",
		time.RFC3339,
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t
		}
	}
	return time.Time{}
}
