package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"sort"
	"time"
)

// Revocation reasons (RFC 5280 section 5.3.1) a user can choose.
var reasonCodes = map[string]int{
	"unspecified":          0,
	"keyCompromise":        1,
	"affiliationChanged":   3,
	"superseded":           4,
	"cessationOfOperation": 5,
}

// ReasonCode maps a reason name to its CRL reason code.
func ReasonCode(name string) (int, error) {
	code, ok := reasonCodes[name]
	if !ok {
		return 0, fmt.Errorf("unknown revocation reason %q (use one of %v)", name, ReasonNames())
	}
	return code, nil
}

// ReasonNames lists the accepted reason names.
func ReasonNames() []string {
	names := make([]string, 0, len(reasonCodes))
	for n := range reasonCodes {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// RevokedCert is one CRL entry.
type RevokedCert struct {
	Serial    *big.Int
	RevokedAt time.Time
	Reason    int
}

// CRLParams describes one CRL issue.
type CRLParams struct {
	Number     *big.Int
	ThisUpdate time.Time
	NextUpdate time.Time
	Revoked    []RevokedCert
}

// CreateCRL signs a DER-encoded X.509 v2 CRL. The issuer must carry a subject
// key identifier and the cRLSign key usage.
func CreateCRL(p CRLParams, issuer *x509.Certificate, key crypto.Signer) ([]byte, error) {
	if issuer.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return nil, fmt.Errorf("%q has no cRLSign key usage and cannot sign a CRL", issuer.Subject.CommonName)
	}
	entries := make([]x509.RevocationListEntry, 0, len(p.Revoked))
	for _, r := range p.Revoked {
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   r.Serial,
			RevocationTime: r.RevokedAt.UTC().Truncate(time.Second),
			ReasonCode:     r.Reason, // 0 (unspecified) is omitted, as RFC 5280 asks
		})
	}
	return x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    p.Number,
		ThisUpdate:                p.ThisUpdate.UTC().Truncate(time.Second),
		NextUpdate:                p.NextUpdate.UTC().Truncate(time.Second),
		RevokedCertificateEntries: entries,
	}, issuer, key)
}
