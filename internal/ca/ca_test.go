package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/burakberkkeskin/crtforge/internal/pki"
)

const baseURL = "http://pki.example.test"

func initOpts(name string) InitOptions {
	return InitOptions{
		Name:             name,
		BaseURL:          baseURL + "/",
		KeyAlgorithm:     pki.ECDSA, // fast; RSA is covered by the import test
		RootDays:         DefaultRootDays,
		Intermediate:     DefaultIntermediate,
		IntermediateDays: DefaultIntermediateDays,
		CRLDays:          DefaultCRLDays,
	}
}

func newCA(t *testing.T) (Home, *CA) {
	t.Helper()
	h := Home(t.TempDir())
	if _, err := Init(h, initOpts("lab")); err != nil {
		t.Fatal(err)
	}
	c, err := Open(h, "lab")
	if err != nil {
		t.Fatal(err)
	}
	return h, c
}

func issue(t *testing.T, c *CA, name string, sans ...string) *Leaf {
	t.Helper()
	l, err := c.Issue(name, IssueOptions{SANs: sans, Days: DefaultLeafDays})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func readCRL(t *testing.T, c *CA, issuer string) *x509.RevocationList {
	t.Helper()
	der, err := os.ReadFile(filepath.Join(c.PublishDir, issuer+".crl"))
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	return crl
}

func TestInitLayout(t *testing.T) {
	h, c := newCA(t)
	if c.Config.BaseURL != baseURL {
		t.Errorf("base URL not normalized: %q", c.Config.BaseURL)
	}
	for path, perm := range map[string]os.FileMode{
		"root/privkey.pem":               privatePerm,
		"root/cert.pem":                  publicPerm,
		"intermediates/int1/privkey.pem": privatePerm,
		"ca.json":                        privatePerm,
	} {
		info, err := os.Stat(filepath.Join(c.Dir, path))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != perm {
			t.Errorf("%s mode %v, want %v", path, info.Mode().Perm(), perm)
		}
	}
	info, _ := os.Stat(c.Dir)
	if info.Mode().Perm() != dirPerm {
		t.Errorf("CA dir mode %v", info.Mode().Perm())
	}
	for _, f := range []string{"root.crt", "root.crl", "int1.crt", "int1.crl"} {
		if _, err := os.Stat(filepath.Join(c.PublishDir, f)); err != nil {
			t.Errorf("publish file missing: %v", err)
		}
	}
	inter := c.Intermediates["int1"]
	if got := inter.Cert.CRLDistributionPoints; len(got) != 1 || got[0] != baseURL+"/lab/root.crl" {
		t.Errorf("intermediate CDP = %v", got)
	}
	if err := readCRL(t, c, "root").CheckSignatureFrom(c.Root.Cert); err != nil {
		t.Errorf("root CRL: %v", err)
	}
	if err := readCRL(t, c, "int1").CheckSignatureFrom(inter.Cert); err != nil {
		t.Errorf("intermediate CRL: %v", err)
	}
	if names, _ := h.List(); len(names) != 1 || names[0] != "lab" {
		t.Errorf("List = %v", names)
	}
	if _, err := Init(h, initOpts("lab")); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("second init: %v", err)
	}
}

func TestInitFailureLeavesNothing(t *testing.T) {
	h := Home(t.TempDir())
	o := initOpts("lab")
	o.IntermediateDays = DefaultRootDays + 1 // outlives the root
	if _, err := Init(h, o); err == nil {
		t.Fatal("expected an error")
	}
	if ok, _ := exists(h.caDir("lab")); ok {
		t.Error("half-created CA left behind")
	}
	if ok, _ := exists(h.publishDir("lab")); ok {
		t.Error("half-created publish dir left behind")
	}
}

func TestInitValidation(t *testing.T) {
	h := Home(t.TempDir())
	for name, mutate := range map[string]func(*InitOptions){
		"bad CA name":         func(o *InitOptions) { o.Name = "../x" },
		"reserved name":       func(o *InitOptions) { o.Intermediate = "root" },
		"ftp base URL":        func(o *InitOptions) { o.BaseURL = "ftp://pki.test" },
		"base URL with query": func(o *InitOptions) { o.BaseURL = "http://pki.test/?a=b" },
		"zero CRL days":       func(o *InitOptions) { o.CRLDays = 0 },
		"zero root days":      func(o *InitOptions) { o.RootDays = 0 },
	} {
		o := initOpts("lab")
		mutate(&o)
		if _, err := Init(h, o); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestIssueFiles(t *testing.T) {
	_, c := newCA(t)
	l := issue(t, c, "web", "app.example.test", "*.example.test", "10.0.0.5")

	read := func(f string) []byte {
		data, err := os.ReadFile(filepath.Join(l.Dir, f))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	certs := func(f string) []*x509.Certificate {
		var out []*x509.Certificate
		rest := read(f)
		for {
			var b *pem.Block
			b, rest = pem.Decode(rest)
			if b == nil {
				return out
			}
			cert, err := x509.ParseCertificate(b.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, cert)
		}
	}
	full := certs("fullchain.pem")
	if len(full) != 2 || !full[0].Equal(l.Cert) || !full[1].Equal(c.Intermediates["int1"].Cert) {
		t.Error("fullchain.pem must be leaf + intermediate, without the root")
	}
	if ca := certs("ca.pem"); len(ca) != 1 || !ca[0].Equal(c.Root.Cert) {
		t.Error("ca.pem must be the root")
	}
	key, err := pki.ParsePrivateKey(read("privkey.pem"))
	if err != nil || !pki.KeyMatches(l.Cert, key) {
		t.Errorf("privkey.pem does not match: %v", err)
	}
	if !strings.HasPrefix(string(read("privkey.pem")), "-----BEGIN PRIVATE KEY-----") {
		t.Error("key is not PKCS #8")
	}
	if got := l.Cert.CRLDistributionPoints; len(got) != 1 || got[0] != baseURL+"/lab/int1.crl" {
		t.Errorf("leaf CDP = %v", got)
	}
	if got := l.Cert.NotAfter.Sub(l.Cert.NotBefore); got != DefaultLeafDays*24*time.Hour {
		t.Errorf("validity span %v", got)
	}

	if _, err := c.Issue("web", IssueOptions{SANs: []string{"x.test"}, Days: 30}); err == nil {
		t.Error("duplicate name accepted without --force")
	}
	if _, err := c.Issue("other", IssueOptions{SANs: []string{"x.test"}, Days: 30, Intermediate: "nope"}); err == nil {
		t.Error("unknown intermediate accepted")
	}
	if _, err := c.Issue("../evil", IssueOptions{SANs: []string{"x.test"}, Days: 30}); err == nil {
		t.Error("path traversal name accepted")
	}
}

func TestForceReplacesAtomically(t *testing.T) {
	_, c := newCA(t)
	first := issue(t, c, "web", "a.test")
	second, err := c.Issue("web", IssueOptions{SANs: []string{"b.test"}, Days: 30, Force: true})
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := c.Leaf("web")
	if err != nil {
		t.Fatal(err)
	}
	if !reloaded.Cert.Equal(second.Cert) || reloaded.Meta.SANs[0] != "b.test" {
		t.Error("forced issue did not replace the certificate")
	}
	entries, _ := os.ReadDir(filepath.Join(c.Dir, "certs"))
	if len(entries) != 1 {
		t.Errorf("leftover staging or backup dirs: %v", entries)
	}
	if len(c.Intermediates["int1"].State.Issued) != 2 || first.Meta.Serial == second.Meta.Serial {
		t.Error("both serials must stay in the issuer state")
	}
}

func TestRevokeAndCRL(t *testing.T) {
	h, c := newCA(t)
	l := issue(t, c, "web", "a.test")
	before := readCRL(t, c, "int1").Number

	if _, err := c.Revoke("web", "keyCompromise"); err != nil {
		t.Fatal(err)
	}
	crl := readCRL(t, c, "int1")
	if crl.Number.Cmp(before) <= 0 {
		t.Error("CRL number did not increase")
	}
	if len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].SerialNumber.Cmp(l.Cert.SerialNumber) != 0 || crl.RevokedCertificateEntries[0].ReasonCode != 1 {
		t.Errorf("CRL entries = %+v", crl.RevokedCertificateEntries)
	}
	if _, err := c.Revoke("web", "keyCompromise"); err == nil {
		t.Error("second revoke accepted")
	}
	if _, err := c.Revoke("web", "bogus"); err == nil {
		t.Error("bogus reason accepted")
	}

	// State survives a reopen; renew issues a fresh, unrevoked certificate.
	c2, err := Open(h, "lab")
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := c2.Leaf("web"); got.Revoked == nil {
		t.Error("revocation lost after reopen")
	}
	renewed, err := c2.Renew("web", RenewOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if renewed.Revoked != nil || renewed.Meta.SANs[0] != "a.test" {
		t.Errorf("renewed = %+v", renewed.Meta)
	}

	if err := c2.RefreshCRLs(); err != nil {
		t.Fatal(err)
	}
	if n := readCRL(t, c2, "int1").Number; n.Cmp(crl.Number) <= 0 {
		t.Error("refresh did not bump the CRL number")
	}
	if len(readCRL(t, c2, "int1").RevokedCertificateEntries) != 1 {
		t.Error("refresh dropped the revoked entry")
	}
}

func TestExpiredRevocationsArePruned(t *testing.T) {
	_, c := newCA(t)
	l := issue(t, c, "web", "a.test")
	if _, err := c.Revoke("web", "superseded"); err != nil {
		t.Fatal(err)
	}
	defer func() { now = time.Now }()
	now = func() time.Time { return l.Cert.NotAfter.Add(time.Hour) }
	if err := c.RefreshCRLs(); err != nil {
		t.Fatal(err)
	}
	if n := len(readCRL(t, c, "int1").RevokedCertificateEntries); n != 0 {
		t.Errorf("expired revoked certificate still listed (%d entries)", n)
	}
}

func TestNameConstraintsRefuseIssue(t *testing.T) {
	h := Home(t.TempDir())
	o := initOpts("lab")
	o.Constraints = Constraints{DNSDomains: []string{"example.test"}}
	c, err := Init(h, o)
	if err != nil {
		t.Fatal(err)
	}
	issue(t, c, "ok", "a.example.test")
	if _, err := c.Issue("bad", IssueOptions{SANs: []string{"evil.test"}, Days: 30}); err == nil {
		t.Error("certificate outside the name constraints was written")
	}
	if ok, _ := exists(filepath.Join(c.Dir, "certs", "bad")); ok {
		t.Error("refused certificate left files")
	}
}

func TestNoBaseURL(t *testing.T) {
	h := Home(t.TempDir())
	o := initOpts("lab")
	o.BaseURL = ""
	c, err := Init(h, o)
	if err != nil {
		t.Fatal(err)
	}
	l := issue(t, c, "web", "a.test")
	if len(l.Cert.CRLDistributionPoints) != 0 || len(c.Intermediates["int1"].Cert.CRLDistributionPoints) != 0 {
		t.Error("CDP present without a base URL")
	}
}

func TestAddIntermediate(t *testing.T) {
	_, c := newCA(t)
	if _, err := c.AddIntermediate("backend", 365, Constraints{}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.AddIntermediate("backend", 365, Constraints{}); err == nil {
		t.Error("duplicate intermediate accepted")
	}
	l, err := c.Issue("api", IssueOptions{SANs: []string{"api.test"}, Days: 30, Intermediate: "backend"})
	if err != nil {
		t.Fatal(err)
	}
	if l.Cert.Issuer.CommonName != c.Intermediates["backend"].Cert.Subject.CommonName {
		t.Error("wrong issuer")
	}
	if len(c.Root.State.Issued) != 2 {
		t.Errorf("root state has %d intermediates", len(c.Root.State.Issued))
	}
}

func TestPFX(t *testing.T) {
	_, c := newCA(t)
	l, err := c.Issue("web", IssueOptions{SANs: []string{"a.test"}, Days: 30, PFX: true, PFXPassword: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(l.Dir, "cert.pfx"))
	if err != nil || info.Mode().Perm() != privatePerm {
		t.Errorf("cert.pfx: %v %v", info, err)
	}
	if _, err := c.Issue("web2", IssueOptions{SANs: []string{"a.test"}, Days: 30, PFX: true}); err == nil {
		t.Error("PFX without password accepted")
	}
}

// writeV1 builds a directory shaped like crtforge v1's: rootCA/rootCA.crt and
// a PKCS #1 rootCA.key.
func writeV1(t *testing.T, ku x509.KeyUsage) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Crtforge ROOT CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(20, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              ku,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "rootCA"), 0o700); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "rootCA", "rootCA.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "rootCA", "rootCA.key"), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600)
	return dir
}

func TestImportV1(t *testing.T) {
	v1 := writeV1(t, x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign|x509.KeyUsageCRLSign)
	v1Root, _ := os.ReadFile(filepath.Join(v1, "rootCA", "rootCA.crt"))
	h := Home(t.TempDir())
	o := initOpts("mylab")
	o.KeyAlgorithm = "" // taken from the v1 root
	c, err := ImportV1(h, v1, o)
	if err != nil {
		t.Fatal(err)
	}
	if c.Config.KeyAlgorithm != pki.RSA || c.Config.ImportedFrom == "" {
		t.Errorf("config = %+v", c.Config)
	}
	orig, _ := pki.ParseCertificate(v1Root)
	if !c.Root.Cert.Equal(orig) {
		t.Fatal("imported root differs from the v1 root")
	}
	l := issue(t, c, "svc", "svc.test")
	if err := pki.VerifyChain(l.Cert, c.Intermediates["int1"].Cert, orig); err != nil {
		t.Errorf("leaf does not chain to the v1 root: %v", err)
	}
	if err := readCRL(t, c, "root").CheckSignatureFrom(orig); err != nil {
		t.Errorf("root CRL: %v", err)
	}
	if after, _ := os.ReadFile(filepath.Join(v1, "rootCA", "rootCA.crt")); string(after) != string(v1Root) {
		t.Error("v1 directory was modified")
	}

	noCRL := writeV1(t, x509.KeyUsageCertSign)
	if _, err := ImportV1(Home(t.TempDir()), noCRL, initOpts("x")); err == nil || !strings.Contains(err.Error(), "cRLSign") {
		t.Errorf("root without cRLSign: %v", err)
	}
}

// TestOpenSSLInterop checks the chain and CRLs with OpenSSL, the reference
// most TLS stacks agree with.
func TestOpenSSLInterop(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not in PATH")
	}
	_, c := newCA(t)
	l := issue(t, c, "web", "a.test")
	tmp := t.TempDir()
	crls := func() string {
		var out []byte
		for _, iss := range []string{"root", "int1"} {
			der, err := os.ReadFile(filepath.Join(c.PublishDir, iss+".crl"))
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})...)
		}
		path := filepath.Join(tmp, "crls.pem")
		if err := os.WriteFile(path, out, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	verify := func() (string, error) {
		out, err := exec.Command(openssl, "verify", "-crl_check_all", "-CRLfile", crls(),
			"-CAfile", filepath.Join(l.Dir, "ca.pem"),
			"-untrusted", filepath.Join(l.Dir, "chain.pem"),
			"-purpose", "sslserver",
			filepath.Join(l.Dir, "cert.pem")).CombinedOutput()
		return string(out), err
	}
	if out, err := verify(); err != nil {
		t.Fatalf("openssl verify: %v\n%s", err, out)
	}
	if _, err := c.Revoke("web", "keyCompromise"); err != nil {
		t.Fatal(err)
	}
	if out, err := verify(); err == nil || !strings.Contains(out, "revoked") {
		t.Errorf("revoked certificate passed openssl verify: %s", out)
	}
}
