package cli

import (
	"bytes"
	"strings"
	"testing"
)

func run(t *testing.T, home string, args ...string) (string, string, int) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := Execute("test", append([]string{"--home", home, "--ca", "lab"}, args...), &out, &errOut)
	return out.String(), errOut.String(), code
}

func TestWorkflow(t *testing.T) {
	t.Setenv("CRTFORGE_CA", "")
	home := t.TempDir()

	out, _, code := run(t, home, "init", "--key-type", "ecdsa", "--base-url", "http://pki.example.test")
	if code != 0 || !strings.Contains(out, "sudo security add-trusted-cert") || !strings.Contains(out, "http://pki.example.test/lab/int1.crl") {
		t.Fatalf("init: code %d\n%s", code, out)
	}

	out, _, code = run(t, home, "issue", "web", "a.example.test", "10.0.0.1")
	if code != 0 || !strings.Contains(out, "fullchain.pem") {
		t.Fatalf("issue: code %d\n%s", code, out)
	}

	_, errOut, code := run(t, home, "issue", "web", "a.example.test")
	if code != 1 || !strings.Contains(errOut, "already exists") {
		t.Errorf("duplicate issue: code %d, stderr %q", code, errOut)
	}

	if _, _, code = run(t, home, "revoke", "web", "--reason", "superseded"); code != 0 {
		t.Fatal("revoke failed")
	}
	out, _, _ = run(t, home, "list")
	if !strings.Contains(out, "revoked") {
		t.Errorf("list does not show the revocation:\n%s", out)
	}
	out, _, _ = run(t, home, "inspect", "web")
	if !strings.Contains(out, "http://pki.example.test/lab/int1.crl") {
		t.Errorf("inspect:\n%s", out)
	}
	if _, _, code = run(t, home, "renew", "web"); code != 0 {
		t.Error("renew failed")
	}
	if _, _, code = run(t, home, "crl"); code != 0 {
		t.Error("crl failed")
	}
	if _, _, code = run(t, home, "add-intermediate", "backend", "--permit-dns", "example.test"); code != 0 {
		t.Error("add-intermediate failed")
	}
	_, errOut, code = run(t, home, "issue", "x", "evil.test", "--intermediate", "backend")
	if code != 1 || !strings.Contains(errOut, "not permitted") {
		t.Errorf("constraint violation: code %d, %q", code, errOut)
	}
}

func TestErrors(t *testing.T) {
	home := t.TempDir()
	_, errOut, code := run(t, home, "issue", "web", "a.test")
	if code != 1 || !strings.Contains(errOut, "crtforge init --ca lab") {
		t.Errorf("missing CA: code %d, %q", code, errOut)
	}
	if _, _, code = run(t, home, "init", "--key-type", "dsa"); code != 1 {
		t.Error("bad key type accepted")
	}
	_, errOut, code = run(t, home, "init", "--key-type", "ecdsa")
	if code != 0 || !strings.Contains(errOut, "no base URL") {
		t.Errorf("init without base URL: code %d, stderr %q", code, errOut)
	}
	if _, _, code = run(t, home, "issue", "web", "a.test", "--days", "900"); code != 1 {
		t.Error("900-day leaf accepted")
	}
	if _, _, code = run(t, home, "issue", "web"); code != 1 {
		t.Error("issue without names accepted")
	}
}
