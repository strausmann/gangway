package testidp_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/strausmann/gangway/identity/testidp"
)

func TestServesDiscoveryDocument(t *testing.T) {
	idp := testidp.New(t)

	resp, err := http.Get(idp.URL() + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("get discovery: %v", err)
	}
	defer resp.Body.Close()

	var doc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if doc.Issuer != idp.URL() {
		t.Errorf("issuer = %q, want %q", doc.Issuer, idp.URL())
	}
	if doc.JWKSURI == "" {
		t.Error("jwks_uri is empty")
	}
}

func TestRotateChangesKeyID(t *testing.T) {
	idp := testidp.New(t)

	before := fetchKeyID(t, idp.URL())
	idp.Rotate()
	after := fetchKeyID(t, idp.URL())

	if before == after {
		t.Errorf("key id unchanged after rotate: %q", before)
	}
}

func fetchKeyID(t *testing.T, base string) string {
	t.Helper()
	resp, err := http.Get(base + "/keys")
	if err != nil {
		t.Fatalf("get keys: %v", err)
	}
	defer resp.Body.Close()

	var set struct {
		Keys []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(set.Keys))
	}
	return set.Keys[0].Kid
}
