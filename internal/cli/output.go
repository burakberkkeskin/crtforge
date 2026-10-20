package cli

import (
	"fmt"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/burakberkkeskin/crtforge/internal/ca"
	"github.com/burakberkkeskin/crtforge/internal/pki"
)

// warnWithin is how early list and inspect warn about an expiring CRL or
// certificate.
const warnWithin = 30 * 24 * time.Hour

func day(t time.Time) string { return t.UTC().Format(time.DateOnly) }

// shellQuote quotes a path for copy-pasting into a POSIX shell.
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func (a *app) describeCA(c *ca.CA) {
	rootPEM := filepath.Join(c.Root.Dir, "cert.pem")
	w := tabwriter.NewWriter(a.out, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "Root CA\t%s, valid until %s\n", c.Root.Cert.Subject.CommonName, day(c.Root.Cert.NotAfter))
	fmt.Fprintf(w, "\tSHA-256 %s\n", pki.Fingerprint(c.Root.Cert))
	fmt.Fprintf(w, "\t%s\n", rootPEM)
	for _, n := range c.IntermediateNames() {
		iss := c.Intermediates[n]
		label := n
		if n == c.Config.DefaultIntermediate {
			label += " (default)"
		}
		fmt.Fprintf(w, "Intermediate %s\t%s, valid until %s, CRL next update %s\n", label, iss.Cert.Subject.CommonName, day(iss.Cert.NotAfter), day(iss.State.CRLNextUpdate))
	}
	if c.Config.BaseURL != "" {
		fmt.Fprintf(w, "Base URL\t%s\n", c.URL(""))
	} else {
		fmt.Fprintf(w, "Base URL\tnone: certificates carry no CRL Distribution Point or AIA\n")
	}
	fmt.Fprintf(w, "Publish dir\t%s%c\n", c.PublishDir, filepath.Separator)
	_ = w.Flush()

	if c.Config.BaseURL != "" {
		a.printf("\nServe the publish directory over plain HTTP (not HTTPS) so %s answers;\n", c.URL(c.Config.DefaultIntermediate+".crl"))
		a.printf("clients that check revocation reject the chain when the CRL is missing or expired.\n")
	} else {
		a.warnf("CA %q has no base URL; clients that check revocation (e.g. .NET/MailKit) will reject its certificates", c.Config.Name)
	}
	a.crlWarnings(c)

	q := shellQuote(rootPEM)
	alias := "crtforge-" + c.Config.Name
	a.printf("\nTrust the root CA (crtforge does not change trust stores):\n")
	tw := tabwriter.NewWriter(a.out, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "  macOS\tsudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s\n", q)
	fmt.Fprintf(tw, "  Debian/Ubuntu\tsudo cp %s /usr/local/share/ca-certificates/%s.crt && sudo update-ca-certificates\n", q, alias)
	fmt.Fprintf(tw, "  RHEL/Fedora\tsudo cp %s /etc/pki/ca-trust/source/anchors/%s.crt && sudo update-ca-trust\n", q, alias)
	fmt.Fprintf(tw, "  Java\tkeytool -importcert -noprompt -alias %s -file %s -keystore <truststore> -storepass <password>\n", alias, q)
	_ = tw.Flush()
}

func (a *app) describeIssued(c *ca.CA, l *ca.Leaf) {
	a.printf("Issued %s (serial %s) by intermediate %s, valid until %s\n\n", l.Meta.Name, l.Meta.Serial, l.Meta.Intermediate, day(l.Cert.NotAfter))
	w := tabwriter.NewWriter(a.out, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "Names\t%s\n", strings.Join(l.Meta.SANs, ", "))
	fmt.Fprintf(w, "Server chain\t%s\n", filepath.Join(l.Dir, "fullchain.pem"))
	fmt.Fprintf(w, "Private key\t%s\n", filepath.Join(l.Dir, "privkey.pem"))
	fmt.Fprintf(w, "Root CA\t%s\n", filepath.Join(l.Dir, "ca.pem"))
	if l.Meta.PFX {
		fmt.Fprintf(w, "PFX\t%s\n", filepath.Join(l.Dir, "cert.pfx"))
	}
	_ = w.Flush()
	if c.Config.BaseURL == "" {
		a.warnf("no CRL Distribution Point: CA %q has no base URL", c.Config.Name)
	}
}

func (a *app) describeLeaf(l *ca.Leaf) {
	w := tabwriter.NewWriter(a.out, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "Certificate\t%s\n", l.Meta.Name)
	fmt.Fprintf(w, "Names\t%s\n", strings.Join(l.Meta.SANs, ", "))
	fmt.Fprintf(w, "Serial\t%s\n", l.Meta.Serial)
	fmt.Fprintf(w, "Issuer\t%s (intermediate %s)\n", l.Cert.Issuer.CommonName, l.Meta.Intermediate)
	fmt.Fprintf(w, "Valid\t%s to %s\n", day(l.Cert.NotBefore), day(l.Cert.NotAfter))
	fmt.Fprintf(w, "Status\t%s\n", leafStatus(l))
	if len(l.Cert.CRLDistributionPoints) > 0 {
		fmt.Fprintf(w, "CRL\t%s\n", strings.Join(l.Cert.CRLDistributionPoints, ", "))
	}
	fmt.Fprintf(w, "SHA-256\t%s\n", pki.Fingerprint(l.Cert))
	fmt.Fprintf(w, "Directory\t%s\n", l.Dir)
	_ = w.Flush()
}

func (a *app) list(c *ca.CA) error {
	leaves, err := c.Leaves()
	if err != nil {
		return err
	}
	base := c.Config.BaseURL
	if base == "" {
		base = "none"
	}
	a.printf("CA %s: root valid until %s, base URL %s\n", c.Config.Name, day(c.Root.Cert.NotAfter), base)
	w := tabwriter.NewWriter(a.out, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "  INTERMEDIATE\tVALID UNTIL\tCRL NEXT UPDATE\n")
	for _, n := range c.IntermediateNames() {
		iss := c.Intermediates[n]
		label := n
		if n == c.Config.DefaultIntermediate {
			label += " *"
		}
		fmt.Fprintf(w, "  %s\t%s\t%s\n", label, day(iss.Cert.NotAfter), day(iss.State.CRLNextUpdate))
	}
	_ = w.Flush()
	if len(leaves) > 0 {
		w = tabwriter.NewWriter(a.out, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "  CERTIFICATE\tVALID UNTIL\tSTATUS\tNAMES\n")
		for _, l := range leaves {
			fmt.Fprintf(w, "  %s\t%s\t%s\t%s\n", l.Meta.Name, day(l.Cert.NotAfter), leafStatus(l), strings.Join(l.Meta.SANs, ", "))
		}
		_ = w.Flush()
	}
	a.crlWarnings(c)
	return nil
}

func leafStatus(l *ca.Leaf) string {
	switch left := time.Until(l.Cert.NotAfter); {
	case l.Revoked != nil:
		return fmt.Sprintf("revoked %s (%s)", day(*l.Revoked.RevokedAt), l.Revoked.Reason)
	case left <= 0:
		return "expired"
	case left < warnWithin:
		return fmt.Sprintf("expires in %d days", int(left.Hours()/24))
	}
	return "valid"
}

func (a *app) crlWarnings(c *ca.CA) {
	for _, iss := range c.Issuers() {
		if left := time.Until(iss.State.CRLNextUpdate); left < warnWithin {
			a.warnf("the %s CRL of CA %q is due %s; run 'crtforge crl --ca %s' and publish again", iss.Name, c.Config.Name, day(iss.State.CRLNextUpdate), c.Config.Name)
		}
	}
}

func (a *app) publishHint(c *ca.CA) {
	if c.Config.BaseURL == "" {
		return
	}
	a.printf("Publish %s%c again so %s serves the new CRL.\n", c.PublishDir, filepath.Separator, c.URL(""))
}
