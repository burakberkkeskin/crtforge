// Package ca keeps crtforge's certificate authorities on disk: a root CA, its
// intermediates, the leaves they issued, revocation state and the CRL / AIA
// files to publish.
//
// Layout under the home directory:
//
//	ca/<ca>/ca.json                         settings
//	ca/<ca>/root/{cert.pem,privkey.pem,state.json}
//	ca/<ca>/intermediates/<name>/{cert.pem,privkey.pem,state.json}
//	ca/<ca>/certs/<name>/{cert.pem,chain.pem,fullchain.pem,privkey.pem,ca.pem,meta.json[,cert.pfx]}
//	publish/<ca>/{root.crt,root.crl,<intermediate>.crt,<intermediate>.crl}
package ca

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/burakberkkeskin/crtforge/internal/pki"
)

const (
	schemaVersion = 2
	rootName      = "root"

	// Certificates and CRLs start an hour in the past so clients with a
	// slightly wrong clock accept them.
	backdate = time.Hour

	DefaultRootDays         = 7305 // 20 years
	DefaultIntermediateDays = 3652 // 10 years
	DefaultLeafDays         = 397
	DefaultCRLDays          = 365
	DefaultIntermediate     = "int1"
)

// now is replaced in tests.
var now = time.Now

// validity starts backdate before now and lasts exactly days, so the span a
// client measures (notAfter - notBefore) is what the user asked for.
func validity(days int) pki.Validity {
	start := now().Add(-backdate)
	return pki.Validity{NotBefore: start, NotAfter: start.AddDate(0, 0, days)}
}

// Home is the directory that holds every CA and the publish tree.
type Home string

// DefaultHome is $CRTFORGE_HOME, else $XDG_DATA_HOME/crtforge, else
// ~/.local/share/crtforge. CA keys are data, not configuration, and this
// keeps v2 apart from v1's ~/.config/crtforge.
func DefaultHome() (Home, error) {
	if dir := os.Getenv("CRTFORGE_HOME"); dir != "" {
		return Home(dir), nil
	}
	if dir := os.Getenv("XDG_DATA_HOME"); dir != "" {
		return Home(filepath.Join(dir, "crtforge")), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot find the home directory: %w", err)
	}
	return Home(filepath.Join(home, ".local", "share", "crtforge")), nil
}

func (h Home) caDir(name string) string      { return filepath.Join(string(h), "ca", name) }
func (h Home) publishDir(name string) string { return filepath.Join(string(h), "publish", name) }

// List returns the names of the CAs in the home directory.
func (h Home) List() ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(string(h), "ca"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			if ok, _ := exists(filepath.Join(string(h), "ca", e.Name(), "ca.json")); ok {
				names = append(names, e.Name())
			}
		}
	}
	return names, nil
}

// Config is ca.json.
type Config struct {
	Schema              int           `json:"schema"`
	Name                string        `json:"name"`
	BaseURL             string        `json:"baseURL,omitempty"`
	KeyAlgorithm        pki.Algorithm `json:"keyAlgorithm"`
	CRLDays             int           `json:"crlDays"`
	DefaultIntermediate string        `json:"defaultIntermediate"`
	CreatedAt           time.Time     `json:"createdAt"`
	ImportedFrom        string        `json:"importedFrom,omitempty"`
}

// IssuerState is state.json of the root or an intermediate: every serial it
// signed and its CRL counter.
type IssuerState struct {
	CRLNumber     int64     `json:"crlNumber"`
	CRLNextUpdate time.Time `json:"crlNextUpdate"`
	Issued        []Issued  `json:"issued"`
}

// Issued is a certificate signed by an issuer.
type Issued struct {
	Serial    string     `json:"serial"` // hex
	Name      string     `json:"name"`
	NotAfter  time.Time  `json:"notAfter"`
	RevokedAt *time.Time `json:"revokedAt,omitempty"`
	Reason    string     `json:"reason,omitempty"`
}

// Issuer is the root CA or an intermediate.
type Issuer struct {
	Name  string // "root" or the intermediate name
	Dir   string
	Cert  *x509.Certificate
	State IssuerState
}

func (i *Issuer) key() (crypto.Signer, error) {
	data, err := os.ReadFile(filepath.Join(i.Dir, "privkey.pem"))
	if err != nil {
		return nil, err
	}
	key, err := pki.ParsePrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("%s key: %w", i.Name, err)
	}
	if !pki.KeyMatches(i.Cert, key) {
		return nil, fmt.Errorf("%s: privkey.pem does not match cert.pem", i.Name)
	}
	return key, nil
}

func (i *Issuer) saveState() error { return writeJSON(filepath.Join(i.Dir, "state.json"), i.State) }

// reloadState re-reads state.json; mutating operations call it after taking
// the lock so they never write back a stale copy.
func (i *Issuer) reloadState() error {
	i.State = IssuerState{}
	return readJSON(filepath.Join(i.Dir, "state.json"), &i.State)
}

// CA is one hierarchy: a root and its intermediates.
type CA struct {
	Config        Config
	Dir           string
	PublishDir    string
	Root          *Issuer
	Intermediates map[string]*Issuer
}

// Constraints are optional name constraints for an intermediate.
type Constraints struct {
	DNSDomains []string
	IPRanges   []*net.IPNet
}

// InitOptions configures a new CA.
type InitOptions struct {
	Name             string
	BaseURL          string
	KeyAlgorithm     pki.Algorithm
	RootDays         int
	Intermediate     string
	IntermediateDays int
	CRLDays          int
	Constraints      Constraints
}

func (o *InitOptions) validate() error {
	if err := ValidateName("CA", o.Name); err != nil {
		return err
	}
	if err := validateIntermediateName(o.Intermediate); err != nil {
		return err
	}
	if o.BaseURL != "" {
		u, err := url.Parse(o.BaseURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("invalid base URL %q: want http://host[/path]", o.BaseURL)
		}
		o.BaseURL = strings.TrimRight(o.BaseURL, "/")
	}
	if o.IntermediateDays <= 0 || o.CRLDays <= 0 {
		return errors.New("validity days must be positive")
	}
	return nil
}

func validateIntermediateName(name string) error {
	if err := ValidateName("intermediate", name); err != nil {
		return err
	}
	if name == rootName {
		return fmt.Errorf("%q is reserved for the root CA", rootName)
	}
	return nil
}

// Init creates a new root CA and its first intermediate.
func Init(h Home, o InitOptions) (*CA, error) {
	if err := o.validate(); err != nil {
		return nil, err
	}
	if o.RootDays <= 0 {
		return nil, errors.New("validity days must be positive")
	}
	key, err := pki.GenerateKey(o.KeyAlgorithm, pki.RoleRoot)
	if err != nil {
		return nil, err
	}
	root, err := pki.CreateRoot(pki.RootParams{
		Subject:  pkix.Name{Organization: []string{"Crtforge"}, CommonName: fmt.Sprintf("Crtforge %s Root CA", o.Name)},
		Validity: validity(o.RootDays),
	}, key)
	if err != nil {
		return nil, err
	}
	return create(h, o, root, key, "")
}

// ImportV1 adopts the root CA of a crtforge v1 hierarchy (the directory that
// holds rootCA/rootCA.crt and rootCA/rootCA.key) so machines that already
// trust it keep working, and issues a new intermediate under it. The v1
// directory is only read.
func ImportV1(h Home, v1Dir string, o InitOptions) (*CA, error) {
	if err := o.validate(); err != nil {
		return nil, err
	}
	certPEM, err := os.ReadFile(filepath.Join(v1Dir, "rootCA", "rootCA.crt"))
	if err != nil {
		return nil, fmt.Errorf("read v1 root certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(v1Dir, "rootCA", "rootCA.key"))
	if err != nil {
		return nil, fmt.Errorf("read v1 root key: %w", err)
	}
	root, err := pki.ParseCertificate(certPEM)
	if err != nil {
		return nil, fmt.Errorf("v1 root certificate: %w", err)
	}
	key, err := pki.ParsePrivateKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("v1 root key: %w", err)
	}
	switch {
	case !pki.KeyMatches(root, key):
		return nil, errors.New("v1 root key does not match the root certificate")
	case !root.IsCA || root.KeyUsage&x509.KeyUsageCertSign == 0:
		return nil, errors.New("v1 root certificate is not a CA certificate")
	case root.KeyUsage&x509.KeyUsageCRLSign == 0:
		return nil, errors.New("v1 root certificate cannot sign CRLs (no cRLSign key usage)")
	case len(root.SubjectKeyId) == 0:
		return nil, errors.New("v1 root certificate has no subject key identifier")
	case now().After(root.NotAfter):
		return nil, fmt.Errorf("v1 root certificate expired on %s", root.NotAfter.Format(time.DateOnly))
	}
	alg, err := pki.AlgorithmOf(root.PublicKey)
	if err != nil {
		return nil, err
	}
	o.KeyAlgorithm = alg
	abs, err := filepath.Abs(v1Dir)
	if err != nil {
		return nil, err
	}
	return create(h, o, root, key, abs)
}

// create writes a CA around an existing root certificate and key. On any
// error the partly written CA is removed again.
func create(h Home, o InitOptions, root *x509.Certificate, rootKey crypto.Signer, importedFrom string) (_ *CA, err error) {
	dir := h.caDir(o.Name)
	if err := os.MkdirAll(filepath.Dir(dir), dirPerm); err != nil {
		return nil, err
	}
	if err := os.Mkdir(dir, dirPerm); err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("CA %q already exists in %s", o.Name, dir)
		}
		return nil, err
	}
	pub := h.publishDir(o.Name)
	defer func() {
		if err != nil {
			_ = os.RemoveAll(dir)
			_ = os.RemoveAll(pub)
		}
	}()
	unlock, err := lock(dir)
	if err != nil {
		return nil, err
	}
	defer unlock()

	c := &CA{
		Config: Config{
			Schema:              schemaVersion,
			Name:                o.Name,
			BaseURL:             o.BaseURL,
			KeyAlgorithm:        o.KeyAlgorithm,
			CRLDays:             o.CRLDays,
			DefaultIntermediate: o.Intermediate,
			CreatedAt:           now().UTC(),
			ImportedFrom:        importedFrom,
		},
		Dir:           dir,
		PublishDir:    pub,
		Intermediates: map[string]*Issuer{},
	}
	c.Root, err = c.writeIssuer(rootName, filepath.Join(dir, rootName), root, rootKey)
	if err != nil {
		return nil, err
	}
	if err := writeJSON(filepath.Join(dir, "ca.json"), c.Config); err != nil {
		return nil, err
	}
	if _, err := c.addIntermediate(o.Intermediate, o.IntermediateDays, o.Constraints, rootKey); err != nil {
		return nil, err
	}
	if err := c.writeCRL(c.Root, rootKey); err != nil {
		return nil, err
	}
	return c, nil
}

// Open loads an existing CA.
func Open(h Home, name string) (*CA, error) {
	if err := ValidateName("CA", name); err != nil {
		return nil, err
	}
	dir := h.caDir(name)
	c := &CA{Dir: dir, PublishDir: h.publishDir(name), Intermediates: map[string]*Issuer{}}
	if err := readJSON(filepath.Join(dir, "ca.json"), &c.Config); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("CA %q does not exist in %s (create it with `crtforge init --ca %s`)", name, string(h), name)
		}
		return nil, err
	}
	if c.Config.Schema != schemaVersion {
		return nil, fmt.Errorf("CA %q has schema %d; this crtforge reads schema %d", name, c.Config.Schema, schemaVersion)
	}
	var err error
	if c.Root, err = loadIssuer(rootName, filepath.Join(dir, rootName)); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Join(dir, "intermediates"))
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		iss, err := loadIssuer(e.Name(), filepath.Join(dir, "intermediates", e.Name()))
		if err != nil {
			return nil, err
		}
		c.Intermediates[e.Name()] = iss
	}
	return c, nil
}

func loadIssuer(name, dir string) (*Issuer, error) {
	data, err := os.ReadFile(filepath.Join(dir, "cert.pem"))
	if err != nil {
		return nil, err
	}
	cert, err := pki.ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("%s certificate: %w", name, err)
	}
	iss := &Issuer{Name: name, Dir: dir, Cert: cert}
	if err := readJSON(filepath.Join(dir, "state.json"), &iss.State); err != nil {
		return nil, err
	}
	return iss, nil
}

// IntermediateNames returns the intermediate names in sorted order.
func (c *CA) IntermediateNames() []string {
	names := make([]string, 0, len(c.Intermediates))
	for n := range c.Intermediates {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// AddIntermediate issues another intermediate under the root.
func (c *CA) AddIntermediate(name string, days int, cons Constraints) (*Issuer, error) {
	if err := validateIntermediateName(name); err != nil {
		return nil, err
	}
	if days <= 0 {
		return nil, errors.New("validity days must be positive")
	}
	if _, ok := c.Intermediates[name]; ok {
		return nil, fmt.Errorf("intermediate %q already exists", name)
	}
	unlock, err := lock(c.Dir)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := c.Root.reloadState(); err != nil {
		return nil, err
	}
	rootKey, err := c.Root.key()
	if err != nil {
		return nil, err
	}
	return c.addIntermediate(name, days, cons, rootKey)
}

func (c *CA) addIntermediate(name string, days int, cons Constraints, rootKey crypto.Signer) (*Issuer, error) {
	key, err := pki.GenerateKey(c.Config.KeyAlgorithm, pki.RoleIntermediate)
	if err != nil {
		return nil, err
	}
	cert, err := pki.CreateIntermediate(pki.IntermediateParams{
		Subject: pkix.Name{
			Organization: []string{"Crtforge"},
			CommonName:   fmt.Sprintf("Crtforge %s Intermediate CA (%s)", c.Config.Name, name),
		},
		Validity:            validity(days),
		Revocation:          c.revocation(rootName),
		PermittedDNSDomains: cons.DNSDomains,
		PermittedIPRanges:   cons.IPRanges,
	}, key.Public(), c.Root.Cert, rootKey)
	if err != nil {
		return nil, fmt.Errorf("intermediate %q: %w", name, err)
	}
	if err := pki.VerifyChain(cert, nil, c.Root.Cert); err != nil {
		return nil, fmt.Errorf("intermediate %q does not verify against the root: %w", name, err)
	}
	c.Root.State.Issued = append(c.Root.State.Issued, Issued{Serial: pki.SerialHex(cert.SerialNumber), Name: name, NotAfter: cert.NotAfter})
	if err := c.Root.saveState(); err != nil {
		return nil, err
	}
	iss, err := c.writeIssuer(name, filepath.Join(c.Dir, "intermediates", name), cert, key)
	if err != nil {
		return nil, err
	}
	if err := c.writeCRL(iss, key); err != nil {
		return nil, err
	}
	c.Intermediates[name] = iss
	return iss, nil
}

// writeIssuer stores a CA certificate, its key and an empty state, and
// publishes the certificate for AIA.
func (c *CA) writeIssuer(name, dir string, cert *x509.Certificate, key crypto.Signer) (*Issuer, error) {
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return nil, err
	}
	keyPEM, err := pki.MarshalPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := writeFileAtomic(filepath.Join(dir, "privkey.pem"), keyPEM, privatePerm); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(filepath.Join(dir, "cert.pem"), pki.EncodeCertificates(cert), publicPerm); err != nil {
		return nil, err
	}
	iss := &Issuer{Name: name, Dir: dir, Cert: cert, State: IssuerState{Issued: []Issued{}}}
	if err := iss.saveState(); err != nil {
		return nil, err
	}
	if err := c.ensurePublishDir(); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(filepath.Join(c.PublishDir, name+".crt"), cert.Raw, publicPerm); err != nil {
		return nil, err
	}
	return iss, nil
}

// ensurePublishDir creates publish/<ca> readable by everyone, whatever the
// umask, so copying the tree to a web server keeps it readable there.
func (c *CA) ensurePublishDir() error {
	for _, dir := range []string{filepath.Dir(c.PublishDir), c.PublishDir} {
		if err := os.MkdirAll(dir, publicDirPerm); err != nil {
			return err
		}
		if err := os.Chmod(dir, publicDirPerm); err != nil {
			return err
		}
	}
	return nil
}

// revocation returns the CRL and AIA URLs for certificates issued by the
// named issuer, or nothing when the CA has no base URL.
func (c *CA) revocation(issuer string) pki.Revocation {
	if c.Config.BaseURL == "" {
		return pki.Revocation{}
	}
	return pki.Revocation{CRLURL: c.URL(issuer + ".crl"), IssuerURL: c.URL(issuer + ".crt")}
}

// URL is where a file of the publish directory is served.
func (c *CA) URL(file string) string {
	return c.Config.BaseURL + "/" + c.Config.Name + "/" + file
}

// writeCRL signs a fresh CRL for the issuer and writes it to the publish
// directory. Revoked certificates that have expired are left out.
func (c *CA) writeCRL(iss *Issuer, key crypto.Signer) error {
	t := now()
	var revoked []pki.RevokedCert
	for _, is := range iss.State.Issued {
		if is.RevokedAt == nil || t.After(is.NotAfter) {
			continue
		}
		serial, ok := new(big.Int).SetString(is.Serial, 16)
		if !ok {
			return fmt.Errorf("%s state: bad serial %q", iss.Name, is.Serial)
		}
		code, err := pki.ReasonCode(is.Reason)
		if err != nil {
			return err
		}
		revoked = append(revoked, pki.RevokedCert{Serial: serial, RevokedAt: *is.RevokedAt, Reason: code})
	}
	number := iss.State.CRLNumber + 1
	next := t.AddDate(0, 0, c.Config.CRLDays)
	der, err := pki.CreateCRL(pki.CRLParams{
		Number:     big.NewInt(number),
		ThisUpdate: t.Add(-backdate),
		NextUpdate: next,
		Revoked:    revoked,
	}, iss.Cert, key)
	if err != nil {
		return err
	}
	if err := c.ensurePublishDir(); err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(c.PublishDir, iss.Name+".crl"), der, publicPerm); err != nil {
		return err
	}
	iss.State.CRLNumber = number
	iss.State.CRLNextUpdate = next.UTC().Truncate(time.Second)
	return iss.saveState()
}

// RefreshCRLs re-signs the CRLs of the root and every intermediate, moving
// their next update forward.
func (c *CA) RefreshCRLs() error {
	unlock, err := lock(c.Dir)
	if err != nil {
		return err
	}
	defer unlock()
	for _, iss := range c.Issuers() {
		if err := iss.reloadState(); err != nil {
			return err
		}
		key, err := iss.key()
		if err != nil {
			return err
		}
		if err := c.writeCRL(iss, key); err != nil {
			return fmt.Errorf("%s CRL: %w", iss.Name, err)
		}
	}
	return nil
}

// Issuers returns the root followed by the intermediates in name order.
func (c *CA) Issuers() []*Issuer {
	out := []*Issuer{c.Root}
	for _, n := range c.IntermediateNames() {
		out = append(out, c.Intermediates[n])
	}
	return out
}
