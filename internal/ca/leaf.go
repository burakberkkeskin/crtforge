package ca

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/burakberkkeskin/crtforge/internal/pki"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// LeafMeta is meta.json of an issued certificate. It records what is needed
// to renew the certificate with the same settings.
type LeafMeta struct {
	Name         string    `json:"name"`
	Intermediate string    `json:"intermediate"`
	SANs         []string  `json:"sans"`
	Days         int       `json:"days"`
	ClientAuth   bool      `json:"clientAuth,omitempty"`
	PFX          bool      `json:"pfx,omitempty"`
	PFXLegacy    bool      `json:"pfxLegacy,omitempty"`
	Serial       string    `json:"serial"`
	IssuedAt     time.Time `json:"issuedAt"`
	NotAfter     time.Time `json:"notAfter"`
}

// Leaf is an issued certificate as found on disk.
type Leaf struct {
	Meta    LeafMeta
	Dir     string
	Cert    *x509.Certificate
	Revoked *Issued // set when the current certificate is revoked
}

// IssueOptions configures a leaf certificate.
type IssueOptions struct {
	Intermediate string // empty means the CA's default intermediate
	SANs         []string
	Days         int
	ClientAuth   bool
	Force        bool // replace an existing certificate of the same name
	PFX          bool
	PFXPassword  string
	PFXLegacy    bool // 3DES/SHA-1 PKCS #12 for old Java and Windows
}

// Issue creates a key and certificate under certs/<name>.
func (c *CA) Issue(name string, o IssueOptions) (*Leaf, error) {
	if err := ValidateName("certificate", name); err != nil {
		return nil, err
	}
	sans, err := pki.ParseSANs(o.SANs)
	if err != nil {
		return nil, err
	}
	if o.Days <= 0 {
		return nil, errors.New("validity days must be positive")
	}
	if o.Intermediate == "" {
		o.Intermediate = c.Config.DefaultIntermediate
	}
	iss, ok := c.Intermediates[o.Intermediate]
	if !ok {
		return nil, fmt.Errorf("intermediate %q does not exist (have: %v)", o.Intermediate, c.IntermediateNames())
	}
	if o.PFX && o.PFXPassword == "" {
		return nil, errors.New("a PFX file needs a password")
	}

	unlock, err := lock(c.Dir)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := iss.reloadState(); err != nil {
		return nil, err
	}

	target := filepath.Join(c.Dir, "certs", name)
	if found, err := exists(target); err != nil {
		return nil, err
	} else if found && !o.Force {
		return nil, fmt.Errorf("certificate %q already exists; use `crtforge renew %s` or --force", name, name)
	}
	issKey, err := iss.key()
	if err != nil {
		return nil, err
	}

	key, err := pki.GenerateKey(c.Config.KeyAlgorithm, pki.RoleLeaf)
	if err != nil {
		return nil, err
	}
	cert, err := pki.CreateLeaf(pki.LeafParams{
		SANs:       sans,
		Validity:   validity(o.Days),
		Revocation: c.revocation(iss.Name),
		ClientAuth: o.ClientAuth,
	}, key.Public(), iss.Cert, issKey)
	if err != nil {
		return nil, err
	}
	// Catches what the template cannot, e.g. a name outside the
	// intermediate's name constraints, before anything is written.
	if err := pki.VerifyChain(cert, iss.Cert, c.Root.Cert); err != nil {
		return nil, fmt.Errorf("refusing to write a certificate that does not verify: %w", err)
	}
	meta := LeafMeta{
		Name:         name,
		Intermediate: iss.Name,
		SANs:         sans.Strings(),
		Days:         o.Days,
		ClientAuth:   o.ClientAuth,
		PFX:          o.PFX,
		PFXLegacy:    o.PFXLegacy,
		Serial:       pki.SerialHex(cert.SerialNumber),
		IssuedAt:     now().UTC().Truncate(time.Second),
		NotAfter:     cert.NotAfter,
	}

	staging, err := c.stageLeaf(meta, cert, key, iss, o)
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(staging) // no-op once renamed into place

	iss.State.Issued = append(iss.State.Issued, Issued{Serial: meta.Serial, Name: name, NotAfter: cert.NotAfter})
	if err := iss.saveState(); err != nil {
		return nil, err
	}
	if err := replaceDir(staging, target); err != nil {
		return nil, err
	}
	return &Leaf{Meta: meta, Dir: target, Cert: cert}, nil
}

// stageLeaf writes every file of a leaf into a temporary directory next to
// its final place, so a replaced certificate is swapped in one rename.
func (c *CA) stageLeaf(meta LeafMeta, cert *x509.Certificate, key crypto.Signer, iss *Issuer, o IssueOptions) (string, error) {
	certsDir := filepath.Join(c.Dir, "certs")
	if err := os.MkdirAll(certsDir, dirPerm); err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp(certsDir, ".staging-"+meta.Name+"-")
	if err != nil {
		return "", err
	}
	keyPEM, err := pki.MarshalPrivateKey(key)
	if err != nil {
		return dir, err
	}
	files := []stagedFile{
		{"privkey.pem", keyPEM, privatePerm},
		{"cert.pem", pki.EncodeCertificates(cert), publicPerm},
		{"chain.pem", pki.EncodeCertificates(iss.Cert), publicPerm},
		{"fullchain.pem", pki.EncodeCertificates(cert, iss.Cert), publicPerm},
		{"ca.pem", pki.EncodeCertificates(c.Root.Cert), publicPerm},
	}
	if o.PFX {
		enc := pkcs12.Modern2023
		if o.PFXLegacy {
			enc = pkcs12.LegacyDES
		}
		pfx, err := enc.Encode(key, cert, []*x509.Certificate{iss.Cert, c.Root.Cert}, o.PFXPassword)
		if err != nil {
			return dir, fmt.Errorf("PFX: %w", err)
		}
		files = append(files, stagedFile{"cert.pfx", pfx, privatePerm})
	}
	for _, f := range files {
		if err := writeFileAtomic(filepath.Join(dir, f.name), f.data, f.perm); err != nil {
			return dir, err
		}
	}
	if err := writeJSON(filepath.Join(dir, "meta.json"), meta); err != nil {
		return dir, err
	}
	return dir, nil
}

type stagedFile struct {
	name string
	data []byte
	perm os.FileMode
}

// replaceDir moves staging to target, replacing an existing target.
func replaceDir(staging, target string) error {
	found, err := exists(target)
	if err != nil {
		return err
	}
	if !found {
		return os.Rename(staging, target)
	}
	old, err := os.MkdirTemp(filepath.Dir(target), ".old-"+filepath.Base(target)+"-")
	if err != nil {
		return err
	}
	if err := os.Remove(old); err != nil { // Rename needs a free name
		return err
	}
	if err := os.Rename(target, old); err != nil {
		return err
	}
	if err := os.Rename(staging, target); err != nil {
		_ = os.Rename(old, target)
		return err
	}
	return os.RemoveAll(old)
}

// RenewOptions overrides settings recorded at issue time.
type RenewOptions struct {
	Days        int // 0 keeps the recorded validity
	PFXPassword string
}

// Renew issues a new key and certificate with the recorded names and
// settings. The previous certificate is not revoked.
func (c *CA) Renew(name string, o RenewOptions) (*Leaf, error) {
	leaf, err := c.Leaf(name)
	if err != nil {
		return nil, err
	}
	m := leaf.Meta
	days := m.Days
	if o.Days > 0 {
		days = o.Days
	}
	return c.Issue(name, IssueOptions{
		Intermediate: m.Intermediate,
		SANs:         m.SANs,
		Days:         days,
		ClientAuth:   m.ClientAuth,
		Force:        true,
		PFX:          m.PFX,
		PFXPassword:  o.PFXPassword,
		PFXLegacy:    m.PFXLegacy,
	})
}

// Revoke marks the current certificate of a leaf as revoked and re-signs
// its intermediate's CRL.
func (c *CA) Revoke(name, reason string) (*Leaf, error) {
	if _, err := pki.ReasonCode(reason); err != nil {
		return nil, err
	}
	unlock, err := lock(c.Dir)
	if err != nil {
		return nil, err
	}
	defer unlock()
	for _, iss := range c.Intermediates {
		if err := iss.reloadState(); err != nil {
			return nil, err
		}
	}
	leaf, err := c.Leaf(name)
	if err != nil {
		return nil, err
	}
	if leaf.Revoked != nil {
		return nil, fmt.Errorf("certificate %q (serial %s) is already revoked", name, leaf.Meta.Serial)
	}
	iss := c.Intermediates[leaf.Meta.Intermediate]
	entry := iss.find(leaf.Meta.Serial)
	if entry == nil {
		return nil, fmt.Errorf("serial %s is not in the state of intermediate %q", leaf.Meta.Serial, iss.Name)
	}
	t := now().UTC().Truncate(time.Second)
	entry.RevokedAt, entry.Reason = &t, reason
	key, err := iss.key()
	if err != nil {
		return nil, err
	}
	if err := c.writeCRL(iss, key); err != nil { // also saves the state
		return nil, err
	}
	leaf.Revoked = entry
	return leaf, nil
}

func (i *Issuer) find(serial string) *Issued {
	for k := range i.State.Issued {
		if i.State.Issued[k].Serial == serial {
			return &i.State.Issued[k]
		}
	}
	return nil
}

// Leaf loads one issued certificate.
func (c *CA) Leaf(name string) (*Leaf, error) {
	if err := ValidateName("certificate", name); err != nil {
		return nil, err
	}
	dir := filepath.Join(c.Dir, "certs", name)
	l := &Leaf{Dir: dir}
	if err := readJSON(filepath.Join(dir, "meta.json"), &l.Meta); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("certificate %q does not exist in CA %q", name, c.Config.Name)
		}
		return nil, err
	}
	data, err := os.ReadFile(filepath.Join(dir, "cert.pem"))
	if err != nil {
		return nil, err
	}
	if l.Cert, err = pki.ParseCertificate(data); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	iss, ok := c.Intermediates[l.Meta.Intermediate]
	if !ok {
		return nil, fmt.Errorf("%s: unknown intermediate %q", name, l.Meta.Intermediate)
	}
	if e := iss.find(l.Meta.Serial); e != nil && e.RevokedAt != nil {
		l.Revoked = e
	}
	return l, nil
}

// Leaves loads every issued certificate, sorted by name.
func (c *CA) Leaves() ([]*Leaf, error) {
	entries, err := os.ReadDir(filepath.Join(c.Dir, "certs"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var leaves []*Leaf
	for _, e := range entries {
		if !e.IsDir() || ValidateName("certificate", e.Name()) != nil {
			continue // staging and backup directories start with a dot
		}
		l, err := c.Leaf(e.Name())
		if err != nil {
			return nil, err
		}
		leaves = append(leaves, l)
	}
	sort.Slice(leaves, func(i, j int) bool { return leaves[i].Meta.Name < leaves[j].Meta.Name })
	return leaves, nil
}
