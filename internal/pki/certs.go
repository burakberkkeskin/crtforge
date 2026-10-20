package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // RFC 5280 key identifier method, not a security use
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

// MaxLeafValidity is the longest leaf validity Apple platforms accept for a
// TLS server certificate, also from a private CA (iOS 13 / macOS 10.15).
const MaxLeafValidity = 825 * 24 * time.Hour

// Revocation information embedded in issued certificates. Both URLs are
// optional; empty means the extension is left out.
type Revocation struct {
	CRLURL    string // CRL Distribution Point of the issuer
	IssuerURL string // AIA caIssuers: the issuer certificate (DER)
}

// Validity is a certificate's lifetime.
type Validity struct {
	NotBefore time.Time
	NotAfter  time.Time
}

// RootParams describes a self-signed root CA.
type RootParams struct {
	Subject pkix.Name
	Validity
}

// IntermediateParams describes a CA certificate signed by the root.
type IntermediateParams struct {
	Subject pkix.Name
	Validity
	Revocation
	// Optional name constraints. Empty means unconstrained.
	PermittedDNSDomains []string
	PermittedIPRanges   []*net.IPNet
}

// LeafParams describes a TLS end-entity certificate.
type LeafParams struct {
	SANs SANs
	Validity
	Revocation
	ClientAuth bool // add clientAuth next to serverAuth
}

// CreateRoot self-signs a root CA certificate.
func CreateRoot(p RootParams, key crypto.Signer) (*x509.Certificate, error) {
	tmpl, err := baseTemplate(p.Subject, p.Validity, key.Public())
	if err != nil {
		return nil, err
	}
	tmpl.IsCA = true
	tmpl.BasicConstraintsValid = true
	tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	return sign(tmpl, tmpl, key.Public(), key)
}

// CreateIntermediate issues a CA certificate that can only sign leaves
// (pathlen 0) for TLS server and client authentication.
func CreateIntermediate(p IntermediateParams, pub crypto.PublicKey, issuer *x509.Certificate, issuerKey crypto.Signer) (*x509.Certificate, error) {
	if err := withinIssuer(p.Validity, issuer); err != nil {
		return nil, err
	}
	tmpl, err := baseTemplate(p.Subject, p.Validity, pub)
	if err != nil {
		return nil, err
	}
	tmpl.IsCA = true
	tmpl.BasicConstraintsValid = true
	tmpl.MaxPathLen = 0
	tmpl.MaxPathLenZero = true
	tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	applyRevocation(tmpl, p.Revocation)
	if len(p.PermittedDNSDomains) > 0 || len(p.PermittedIPRanges) > 0 {
		tmpl.PermittedDNSDomainsCritical = true
		tmpl.PermittedDNSDomains = p.PermittedDNSDomains
		tmpl.PermittedIPRanges = p.PermittedIPRanges
	}
	return sign(tmpl, issuer, pub, issuerKey)
}

// CreateLeaf issues a TLS end-entity certificate.
func CreateLeaf(p LeafParams, pub crypto.PublicKey, issuer *x509.Certificate, issuerKey crypto.Signer) (*x509.Certificate, error) {
	if p.NotAfter.Sub(p.NotBefore) > MaxLeafValidity {
		return nil, fmt.Errorf("leaf validity is longer than 825 days, which Apple platforms reject")
	}
	if err := withinIssuer(p.Validity, issuer); err != nil {
		return nil, err
	}
	names := p.SANs.Strings()
	if len(names) == 0 {
		return nil, errors.New("a leaf certificate needs at least one subject alternative name")
	}
	tmpl, err := baseTemplate(pkix.Name{CommonName: names[0]}, p.Validity, pub)
	if err != nil {
		return nil, err
	}
	tmpl.BasicConstraintsValid = true
	tmpl.DNSNames = p.SANs.DNS
	tmpl.IPAddresses = p.SANs.IPs
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	if _, isRSA := pub.(*rsa.PublicKey); isRSA {
		tmpl.KeyUsage |= x509.KeyUsageKeyEncipherment
	}
	tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	if p.ClientAuth {
		tmpl.ExtKeyUsage = append(tmpl.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	}
	applyRevocation(tmpl, p.Revocation)
	return sign(tmpl, issuer, pub, issuerKey)
}

func baseTemplate(subject pkix.Name, v Validity, pub crypto.PublicKey) (*x509.Certificate, error) {
	if !v.NotAfter.After(v.NotBefore) {
		return nil, errors.New("certificate validity ends before it starts")
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	ski, err := subjectKeyID(pub)
	if err != nil {
		return nil, err
	}
	return &x509.Certificate{
		SerialNumber: serial,
		Subject:      subject,
		NotBefore:    v.NotBefore.UTC().Truncate(time.Second),
		NotAfter:     v.NotAfter.UTC().Truncate(time.Second),
		SubjectKeyId: ski,
	}, nil
}

func applyRevocation(tmpl *x509.Certificate, r Revocation) {
	if r.CRLURL != "" {
		tmpl.CRLDistributionPoints = []string{r.CRLURL}
	}
	if r.IssuerURL != "" {
		tmpl.IssuingCertificateURL = []string{r.IssuerURL}
	}
}

func withinIssuer(v Validity, issuer *x509.Certificate) error {
	if v.NotAfter.UTC().Truncate(time.Second).After(issuer.NotAfter) {
		return fmt.Errorf("requested validity ends %s, after the issuer %q expires (%s)",
			v.NotAfter.UTC().Format(time.DateOnly), issuer.Subject.CommonName, issuer.NotAfter.UTC().Format(time.DateOnly))
	}
	return nil
}

func sign(tmpl, parent *x509.Certificate, pub crypto.PublicKey, key crypto.Signer) (*x509.Certificate, error) {
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// newSerial returns a positive serial with 127 bits of entropy (RFC 5280
// allows up to 20 octets; CA/B Forum asks for at least 64 random bits).
func newSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 127)
	for {
		n, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return nil, err
		}
		if n.Sign() > 0 {
			return n, nil
		}
	}
}

// subjectKeyID is RFC 5280 section 4.2.1.2 method 1: SHA-1 of the
// subjectPublicKey BIT STRING.
func subjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &spki); err != nil {
		return nil, err
	}
	sum := sha1.Sum(spki.SubjectPublicKey.Bytes) //nolint:gosec
	return sum[:], nil
}

// VerifyChain checks cert against root, through intermediate when it is not
// nil, the way a TLS client would: signatures, validity, path length, name
// constraints and extended key usage.
func VerifyChain(cert, intermediate, root *x509.Certificate) error {
	roots := x509.NewCertPool()
	roots.AddCert(root)
	inters := x509.NewCertPool()
	if intermediate != nil {
		inters.AddCert(intermediate)
	}
	_, err := cert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inters,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err
}

// EncodeCertificates PEM-encodes certificates in order.
func EncodeCertificates(certs ...*x509.Certificate) []byte {
	var out []byte
	for _, c := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return out
}

// ParseCertificate reads the first certificate in PEM data.
func ParseCertificate(data []byte) (*x509.Certificate, error) {
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return nil, errors.New("no certificate found in PEM data")
		}
		if block.Type == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
	}
}

// Fingerprint is the SHA-256 fingerprint in the colon-separated upper-case
// form that browsers and `openssl x509 -fingerprint` print.
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	parts := make([]string, 0, len(sum))
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

// SerialHex formats a serial number as lower-case hex.
func SerialHex(n *big.Int) string { return n.Text(16) }
