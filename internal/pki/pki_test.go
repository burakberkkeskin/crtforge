package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

type chain struct {
	root, inter       *x509.Certificate
	rootKey, interKey crypto.Signer
}

func newChain(t *testing.T, alg Algorithm, rev Revocation) chain {
	t.Helper()
	now := time.Now()
	rootKey, err := GenerateKey(alg, RoleRoot)
	if err != nil {
		t.Fatal(err)
	}
	root, err := CreateRoot(RootParams{
		Subject:  pkix.Name{CommonName: "Test Root"},
		Validity: Validity{NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(20, 0, 0)},
	}, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	interKey, err := GenerateKey(alg, RoleIntermediate)
	if err != nil {
		t.Fatal(err)
	}
	inter, err := CreateIntermediate(IntermediateParams{
		Subject:    pkix.Name{CommonName: "Test Intermediate"},
		Validity:   Validity{NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(10, 0, 0)},
		Revocation: rev,
	}, interKey.Public(), root, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	return chain{root: root, inter: inter, rootKey: rootKey, interKey: interKey}
}

func issueLeaf(t *testing.T, c chain, alg Algorithm, sans []string, days int, rev Revocation) (*x509.Certificate, error) {
	t.Helper()
	s, err := ParseSANs(sans)
	if err != nil {
		t.Fatal(err)
	}
	key, err := GenerateKey(alg, RoleLeaf)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	return CreateLeaf(LeafParams{
		SANs:       s,
		Validity:   Validity{NotBefore: now.Add(-time.Hour), NotAfter: now.Add(-time.Hour).AddDate(0, 0, days)},
		Revocation: rev,
	}, key.Public(), c.inter, c.interKey)
}

func TestProfiles(t *testing.T) {
	rev := Revocation{CRLURL: "http://pki.test/ca/int.crl", IssuerURL: "http://pki.test/ca/int.crt"}
	for _, alg := range []Algorithm{RSA, ECDSA} {
		t.Run(string(alg), func(t *testing.T) {
			c := newChain(t, alg, Revocation{CRLURL: "http://pki.test/ca/root.crl"})

			if c.root.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
				t.Errorf("root key usage = %v", c.root.KeyUsage)
			}
			if len(c.root.SubjectKeyId) == 0 || !c.root.IsCA {
				t.Error("root: want CA with subject key identifier")
			}

			if c.inter.MaxPathLen != 0 || !c.inter.MaxPathLenZero {
				t.Error("intermediate: want pathlen 0")
			}
			if c.inter.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
				t.Errorf("intermediate key usage = %v", c.inter.KeyUsage)
			}
			if got := c.inter.CRLDistributionPoints; len(got) != 1 || got[0] != "http://pki.test/ca/root.crl" {
				t.Errorf("intermediate CDP = %v", got)
			}
			if string(c.inter.AuthorityKeyId) != string(c.root.SubjectKeyId) {
				t.Error("intermediate AKI does not match root SKI")
			}

			leaf, err := issueLeaf(t, c, alg, []string{"App.Test.local", "*.test.local", "10.0.0.5"}, 397, rev)
			if err != nil {
				t.Fatal(err)
			}
			if leaf.Subject.CommonName != "app.test.local" {
				t.Errorf("CN = %q", leaf.Subject.CommonName)
			}
			if leaf.IsCA || !leaf.BasicConstraintsValid {
				t.Error("leaf must carry CA:FALSE")
			}
			if len(leaf.SubjectKeyId) == 0 {
				t.Error("leaf has no subject key identifier")
			}
			wantKU := x509.KeyUsageDigitalSignature
			if alg == RSA {
				wantKU |= x509.KeyUsageKeyEncipherment
			}
			if leaf.KeyUsage != wantKU {
				t.Errorf("leaf key usage = %v, want %v", leaf.KeyUsage, wantKU)
			}
			if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
				t.Errorf("leaf EKU = %v", leaf.ExtKeyUsage)
			}
			if got := leaf.CRLDistributionPoints; len(got) != 1 || got[0] != rev.CRLURL {
				t.Errorf("leaf CDP = %v", got)
			}
			if got := leaf.IssuingCertificateURL; len(got) != 1 || got[0] != rev.IssuerURL {
				t.Errorf("leaf AIA = %v", got)
			}
			if leaf.SerialNumber.Sign() <= 0 || leaf.SerialNumber.BitLen() > 127 {
				t.Errorf("serial %v out of range", leaf.SerialNumber)
			}
			if err := VerifyChain(leaf, c.inter, c.root); err != nil {
				t.Fatalf("chain does not verify: %v", err)
			}
			roots := x509.NewCertPool()
			roots.AddCert(c.root)
			inters := x509.NewCertPool()
			inters.AddCert(c.inter)
			for _, host := range []string{"app.test.local", "x.test.local", "10.0.0.5"} {
				if _, err := leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: roots, Intermediates: inters}); err != nil {
					t.Errorf("verify for %s: %v", host, err)
				}
			}
			if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "a.b.test.local", Roots: roots, Intermediates: inters}); err == nil {
				t.Error("wildcard must not match two labels")
			}
		})
	}
}

func TestNoRevocationURLs(t *testing.T) {
	c := newChain(t, ECDSA, Revocation{})
	leaf, err := issueLeaf(t, c, ECDSA, []string{"a.test"}, 30, Revocation{})
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.CRLDistributionPoints)+len(leaf.IssuingCertificateURL)+len(c.inter.CRLDistributionPoints) != 0 {
		t.Error("expected no CDP/AIA without URLs")
	}
}

func TestLeafValidityLimits(t *testing.T) {
	c := newChain(t, ECDSA, Revocation{})
	if _, err := issueLeaf(t, c, ECDSA, []string{"a.test"}, 826, Revocation{}); err == nil || !strings.Contains(err.Error(), "825") {
		t.Errorf("826 days: err = %v", err)
	}
	if _, err := issueLeaf(t, c, ECDSA, []string{"a.test"}, 825, Revocation{}); err != nil {
		t.Errorf("825 days: %v", err)
	}

	// An intermediate must not outlive the root.
	key, _ := GenerateKey(ECDSA, RoleIntermediate)
	_, err := CreateIntermediate(IntermediateParams{
		Subject:  pkix.Name{CommonName: "too long"},
		Validity: Validity{NotBefore: time.Now(), NotAfter: c.root.NotAfter.Add(time.Hour)},
	}, key.Public(), c.root, c.rootKey)
	if err == nil {
		t.Error("intermediate outliving the root was accepted")
	}
}

func TestClientAuth(t *testing.T) {
	c := newChain(t, ECDSA, Revocation{})
	s, _ := ParseSANs([]string{"client.test"})
	key, _ := GenerateKey(ECDSA, RoleLeaf)
	leaf, err := CreateLeaf(LeafParams{
		SANs:       s,
		Validity:   Validity{NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(0, 0, 30)},
		ClientAuth: true,
	}, key.Public(), c.inter, c.interKey)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(c.root)
	inters := x509.NewCertPool()
	inters.AddCert(c.inter)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Errorf("client auth chain: %v", err)
	}
}

func TestNameConstraints(t *testing.T) {
	now := time.Now()
	rootKey, _ := GenerateKey(ECDSA, RoleRoot)
	root, _ := CreateRoot(RootParams{Subject: pkix.Name{CommonName: "R"}, Validity: Validity{NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0)}}, rootKey)
	interKey, _ := GenerateKey(ECDSA, RoleIntermediate)
	_, ipnet, _ := net.ParseCIDR("10.0.0.0/8")
	inter, err := CreateIntermediate(IntermediateParams{
		Subject:             pkix.Name{CommonName: "I"},
		Validity:            Validity{NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0)},
		PermittedDNSDomains: []string{"lab.test"},
		PermittedIPRanges:   []*net.IPNet{ipnet},
	}, interKey.Public(), root, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	if !inter.PermittedDNSDomainsCritical {
		t.Error("name constraints must be critical")
	}
	c := chain{root: root, inter: inter, rootKey: rootKey, interKey: interKey}
	ok, _ := issueLeaf(t, c, ECDSA, []string{"a.lab.test", "10.1.2.3"}, 30, Revocation{})
	if err := VerifyChain(ok, inter, root); err != nil {
		t.Errorf("permitted names: %v", err)
	}
	for _, name := range []string{"evil.test", "192.168.1.1"} {
		bad, _ := issueLeaf(t, c, ECDSA, []string{name}, 30, Revocation{})
		if err := VerifyChain(bad, inter, root); err == nil {
			t.Errorf("%s verified despite name constraints", name)
		}
	}
}

func TestCRL(t *testing.T) {
	c := newChain(t, RSA, Revocation{})
	revokedAt := time.Now().Add(-time.Minute)
	der, err := CreateCRL(CRLParams{
		Number:     big.NewInt(7),
		ThisUpdate: time.Now().Add(-time.Hour),
		NextUpdate: time.Now().AddDate(1, 0, 0),
		Revoked: []RevokedCert{
			{Serial: big.NewInt(42), RevokedAt: revokedAt, Reason: 1},
			{Serial: big.NewInt(43), RevokedAt: revokedAt, Reason: 0},
		},
	}, c.inter, c.interKey)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := crl.CheckSignatureFrom(c.inter); err != nil {
		t.Errorf("CRL signature: %v", err)
	}
	if crl.Number.Int64() != 7 {
		t.Errorf("CRL number = %v", crl.Number)
	}
	if string(crl.AuthorityKeyId) != string(c.inter.SubjectKeyId) {
		t.Error("CRL AKI does not match issuer SKI")
	}
	if len(crl.RevokedCertificateEntries) != 2 || crl.RevokedCertificateEntries[0].ReasonCode != 1 {
		t.Errorf("entries = %+v", crl.RevokedCertificateEntries)
	}
	for _, e := range crl.RevokedCertificateEntries[1].Extensions {
		if e.Id.Equal([]int{2, 5, 29, 21}) {
			t.Error("unspecified reason must be omitted")
		}
	}

	leafKey, _ := GenerateKey(ECDSA, RoleLeaf)
	noCRLSign, _ := CreateRoot(RootParams{Subject: pkix.Name{CommonName: "x"}, Validity: Validity{NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}}, leafKey)
	noCRLSign.KeyUsage = x509.KeyUsageCertSign
	if _, err := CreateCRL(CRLParams{Number: big.NewInt(1), ThisUpdate: time.Now(), NextUpdate: time.Now().Add(time.Hour)}, noCRLSign, leafKey); err == nil {
		t.Error("CRL from an issuer without cRLSign was accepted")
	}
}

func TestReasonCode(t *testing.T) {
	if c, err := ReasonCode("keyCompromise"); err != nil || c != 1 {
		t.Errorf("keyCompromise = %d, %v", c, err)
	}
	if _, err := ReasonCode("bogus"); err == nil {
		t.Error("bogus reason accepted")
	}
}

func TestParsePrivateKeyFormats(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecDER, _ := x509.MarshalECPrivateKey(ecKey)
	pkcs8, _ := MarshalPrivateKey(rsaKey)
	cases := map[string][]byte{
		"pkcs8": pkcs8,
		"pkcs1": pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}),
		"sec1":  append([]byte("junk\n"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER})...),
	}
	for name, data := range cases {
		if _, err := ParsePrivateKey(data); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := ParsePrivateKey(pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte{1}})); err == nil {
		t.Error("encrypted key accepted")
	}
	if _, err := ParsePrivateKey([]byte("nothing")); err == nil {
		t.Error("garbage accepted")
	}
}

func TestKeyMatches(t *testing.T) {
	c := newChain(t, ECDSA, Revocation{})
	if !KeyMatches(c.root, c.rootKey) || KeyMatches(c.root, c.interKey) {
		t.Error("KeyMatches gives the wrong answer")
	}
}

func TestFingerprint(t *testing.T) {
	c := newChain(t, ECDSA, Revocation{})
	fp := Fingerprint(c.root)
	if len(fp) != 32*3-1 || strings.ToUpper(fp) != fp {
		t.Errorf("fingerprint %q", fp)
	}
}
