// Package cli is crtforge's command line.
package cli

import (
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/burakberkkeskin/crtforge/internal/ca"
	"github.com/burakberkkeskin/crtforge/internal/pki"
	"github.com/spf13/cobra"
)

type app struct {
	home   string
	caName string
	out    io.Writer
	errOut io.Writer
}

// Execute runs the command line and returns the process exit code.
func Execute(version string, args []string, stdout, stderr io.Writer) int {
	cmd := NewRootCommand(version)
	cmd.SetArgs(args)
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(stderr, "crtforge: error:", err)
		return 1
	}
	return 0
}

// NewRootCommand builds the command tree.
func NewRootCommand(version string) *cobra.Command {
	a := &app{}
	root := &cobra.Command{
		Use:   "crtforge",
		Short: "A small private CA for test environments",
		Long: `crtforge runs a private certificate authority for test environments:
a root CA, an intermediate and TLS leaf certificates, with CRL Distribution
Points and AIA so clients that check revocation accept the chain.

Start with 'crtforge init', issue certificates with 'crtforge issue', and
serve the files in the publish directory at the CA's base URL.`,
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			a.out, a.errOut = cmd.OutOrStdout(), cmd.ErrOrStderr()
			return nil
		},
	}
	defaultCA := os.Getenv("CRTFORGE_CA")
	if defaultCA == "" {
		defaultCA = "default"
	}
	root.PersistentFlags().StringVar(&a.home, "home", "", "data directory (default $CRTFORGE_HOME, $XDG_DATA_HOME/crtforge or ~/.local/share/crtforge)")
	root.PersistentFlags().StringVar(&a.caName, "ca", defaultCA, "CA to use (default $CRTFORGE_CA or \"default\")")
	root.AddCommand(
		a.initCommand(),
		a.importV1Command(),
		a.addIntermediateCommand(),
		a.issueCommand(),
		a.renewCommand(),
		a.revokeCommand(),
		a.crlCommand(),
		a.listCommand(),
		a.inspectCommand(),
	)
	return root
}

func (a *app) homeDir() (ca.Home, error) {
	if a.home != "" {
		return ca.Home(a.home), nil
	}
	return ca.DefaultHome()
}

func (a *app) open() (*ca.CA, error) {
	h, err := a.homeDir()
	if err != nil {
		return nil, err
	}
	return ca.Open(h, a.caName)
}

func (a *app) printf(format string, args ...any) { fmt.Fprintf(a.out, format, args...) }
func (a *app) warnf(format string, args ...any) {
	fmt.Fprintf(a.errOut, "warning: "+format+"\n", args...)
}

// caFlags are shared by init and import-v1.
type caFlags struct {
	baseURL          string
	keyType          string
	rootDays         int
	intermediate     string
	intermediateDays int
	crlDays          int
	constraints      constraintFlags
}

type constraintFlags struct {
	dns []string
	ips []string
}

func (f *constraintFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringSliceVar(&f.dns, "permit-dns", nil, "name constraint: DNS domains the intermediate may issue for (e.g. example.test)")
	cmd.Flags().StringSliceVar(&f.ips, "permit-ip", nil, "name constraint: IP ranges in CIDR form the intermediate may issue for")
}

func (f *constraintFlags) parse() (ca.Constraints, error) {
	c := ca.Constraints{DNSDomains: f.dns}
	for _, s := range f.ips {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return ca.Constraints{}, fmt.Errorf("--permit-ip %q: %w", s, err)
		}
		c.IPRanges = append(c.IPRanges, n)
	}
	return c, nil
}

func (f *caFlags) register(cmd *cobra.Command, withRoot bool) {
	cmd.Flags().StringVar(&f.baseURL, "base-url", "", "HTTP URL the publish directory is served at, embedded as CRL Distribution Point and AIA (e.g. http://pki.example.test)")
	if withRoot {
		cmd.Flags().StringVar(&f.keyType, "key-type", string(pki.RSA), "key algorithm: rsa or ecdsa")
		cmd.Flags().IntVar(&f.rootDays, "root-days", ca.DefaultRootDays, "root CA validity in days")
	}
	cmd.Flags().StringVar(&f.intermediate, "intermediate", ca.DefaultIntermediate, "name of the first intermediate CA")
	cmd.Flags().IntVar(&f.intermediateDays, "intermediate-days", ca.DefaultIntermediateDays, "intermediate CA validity in days")
	cmd.Flags().IntVar(&f.crlDays, "crl-days", ca.DefaultCRLDays, "CRL validity in days, fixed when the CA is created; run 'crtforge crl' before it ends (e.g. 3650 if you never revoke)")
	f.constraints.register(cmd)
}

func (f *caFlags) options(name string) (ca.InitOptions, error) {
	cons, err := f.constraints.parse()
	if err != nil {
		return ca.InitOptions{}, err
	}
	o := ca.InitOptions{
		Name:             name,
		BaseURL:          f.baseURL,
		RootDays:         f.rootDays,
		Intermediate:     f.intermediate,
		IntermediateDays: f.intermediateDays,
		CRLDays:          f.crlDays,
		Constraints:      cons,
	}
	if f.keyType != "" {
		if o.KeyAlgorithm, err = pki.ParseAlgorithm(f.keyType); err != nil {
			return ca.InitOptions{}, err
		}
	}
	return o, nil
}

func (a *app) initCommand() *cobra.Command {
	var f caFlags
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create a root CA and its first intermediate",
		Example: `  crtforge init --ca lab --base-url http://pki.example.test
  crtforge init --ca lab --key-type ecdsa --permit-dns example.test`,
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			h, err := a.homeDir()
			if err != nil {
				return err
			}
			o, err := f.options(a.caName)
			if err != nil {
				return err
			}
			c, err := ca.Init(h, o)
			if err != nil {
				return err
			}
			a.printf("Created CA %q in %s\n\n", c.Config.Name, c.Dir)
			a.describeCA(c)
			return nil
		},
	}
	f.register(cmd, true)
	return cmd
}

func (a *app) importV1Command() *cobra.Command {
	var f caFlags
	cmd := &cobra.Command{
		Use:   "import-v1 <v1-ca-dir>",
		Short: "Adopt a crtforge v1 root CA and issue a new intermediate under it",
		Long: `import-v1 copies the root CA of a crtforge v1 hierarchy (the directory that
holds rootCA/, e.g. ~/.config/crtforge/mylab) into a new v2 CA, so the
machines that already trust that root keep working. A new intermediate with
CRL Distribution Points is issued under it. The v1 directory is not changed.`,
		Example: `  crtforge import-v1 --ca mylab --base-url http://pki.example.test ~/.config/crtforge/mylab`,
		Args:    cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			h, err := a.homeDir()
			if err != nil {
				return err
			}
			o, err := f.options(a.caName)
			if err != nil {
				return err
			}
			c, err := ca.ImportV1(h, args[0], o)
			if err != nil {
				return err
			}
			a.printf("Imported the v1 root from %s as CA %q in %s\n\n", args[0], c.Config.Name, c.Dir)
			a.describeCA(c)
			return nil
		},
	}
	f.register(cmd, false)
	return cmd
}

func (a *app) addIntermediateCommand() *cobra.Command {
	var (
		days int
		cons constraintFlags
	)
	cmd := &cobra.Command{
		Use:   "add-intermediate <name>",
		Short: "Issue another intermediate CA under the root",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			c, err := a.open()
			if err != nil {
				return err
			}
			cc, err := cons.parse()
			if err != nil {
				return err
			}
			iss, err := c.AddIntermediate(args[0], days, cc)
			if err != nil {
				return err
			}
			a.printf("Added intermediate %q (%s), valid until %s\n", iss.Name, iss.Cert.Subject.CommonName, day(iss.Cert.NotAfter))
			a.printf("Publish %s again so its certificate and CRL are served.\n", c.PublishDir)
			return nil
		},
	}
	cmd.Flags().IntVar(&days, "days", ca.DefaultIntermediateDays, "validity in days")
	cons.register(cmd)
	return cmd
}

type leafFlags struct {
	intermediate string
	days         int
	clientAuth   bool
	force        bool
	pfx          bool
	pfxPassword  string
	pfxLegacy    bool
}

func (a *app) issueCommand() *cobra.Command {
	var f leafFlags
	cmd := &cobra.Command{
		Use:   "issue <name> <dns-name-or-ip>...",
		Short: "Issue a TLS certificate",
		Long: `issue creates a key and a certificate under certs/<name>:

  fullchain.pem  leaf + intermediate, what a server presents
  privkey.pem    the leaf key (PKCS #8)
  cert.pem       the leaf alone
  chain.pem      the intermediate alone
  ca.pem         the root, for trust stores
  cert.pfx       with --pfx: key + leaf + intermediate + root

The first name becomes the subject common name. Quote wildcards ("*.example.test").`,
		Example: `  crtforge issue web app.example.test "*.example.test" 10.0.0.5
  crtforge issue gitlab gitlab.example.test --pfx --pfx-password secret`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			c, err := a.open()
			if err != nil {
				return err
			}
			leaf, err := c.Issue(args[0], ca.IssueOptions{
				Intermediate: f.intermediate,
				SANs:         args[1:],
				Days:         f.days,
				ClientAuth:   f.clientAuth,
				Force:        f.force,
				PFX:          f.pfx,
				PFXPassword:  f.pfxPassword,
				PFXLegacy:    f.pfxLegacy,
			})
			if err != nil {
				return err
			}
			a.describeIssued(c, leaf)
			return nil
		},
	}
	cmd.Flags().StringVar(&f.intermediate, "intermediate", "", "intermediate to sign with (default: the CA's default intermediate)")
	cmd.Flags().IntVar(&f.days, "days", ca.DefaultLeafDays, "validity in days (at most 825, the Apple limit)")
	cmd.Flags().BoolVar(&f.clientAuth, "client", false, "also allow TLS client authentication (mTLS)")
	cmd.Flags().BoolVar(&f.force, "force", false, "replace an existing certificate with the same name")
	registerPFXFlags(cmd, &f.pfx, &f.pfxPassword, &f.pfxLegacy)
	return cmd
}

func registerPFXFlags(cmd *cobra.Command, pfx *bool, password *string, legacy *bool) {
	if pfx != nil {
		cmd.Flags().BoolVar(pfx, "pfx", false, "also write cert.pfx (PKCS #12)")
	}
	cmd.Flags().StringVar(password, "pfx-password", "changeit", "PFX password")
	if legacy != nil {
		cmd.Flags().BoolVar(legacy, "pfx-legacy", false, "use 3DES/SHA-1 PFX encryption for old Java and Windows")
	}
}

func (a *app) renewCommand() *cobra.Command {
	var o ca.RenewOptions
	cmd := &cobra.Command{
		Use:   "renew <name>",
		Short: "Re-issue a certificate with a new key and the same names",
		Long:  "renew issues a new key and certificate with the names and settings recorded at issue time. The old certificate is not revoked; run 'crtforge revoke' first if it must be.",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			c, err := a.open()
			if err != nil {
				return err
			}
			leaf, err := c.Renew(args[0], o)
			if err != nil {
				return err
			}
			a.describeIssued(c, leaf)
			return nil
		},
	}
	cmd.Flags().IntVar(&o.Days, "days", 0, "validity in days (default: as at issue time)")
	registerPFXFlags(cmd, nil, &o.PFXPassword, nil)
	return cmd
}

func (a *app) revokeCommand() *cobra.Command {
	var reason string
	cmd := &cobra.Command{
		Use:   "revoke <name>",
		Short: "Revoke a certificate and re-sign its intermediate's CRL",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			c, err := a.open()
			if err != nil {
				return err
			}
			leaf, err := c.Revoke(args[0], reason)
			if err != nil {
				return err
			}
			a.printf("Revoked %s (serial %s, reason %s).\n", leaf.Meta.Name, leaf.Meta.Serial, reason)
			a.publishHint(c)
			return nil
		},
	}
	cmd.Flags().StringVar(&reason, "reason", "unspecified", "reason: "+strings.Join(pki.ReasonNames(), ", "))
	return cmd
}

func (a *app) crlCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "crl",
		Short: "Re-sign every CRL of the CA with a new next-update time",
		Long:  "crl re-signs the root and intermediate CRLs. Run it before the CRLs' next update (see 'crtforge list') and publish the files again; clients that check revocation reject an expired CRL.",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			c, err := a.open()
			if err != nil {
				return err
			}
			if err := c.RefreshCRLs(); err != nil {
				return err
			}
			a.printf("CRLs re-signed, next update %s.\n", day(c.Root.State.CRLNextUpdate))
			a.publishHint(c)
			return nil
		},
	}
}

func (a *app) listCommand() *cobra.Command {
	var all bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List CAs, intermediates and certificates with their expiry",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			h, err := a.homeDir()
			if err != nil {
				return err
			}
			names := []string{a.caName}
			if all {
				if names, err = h.List(); err != nil {
					return err
				}
				if len(names) == 0 {
					a.printf("No CAs in %s.\n", string(h))
					return nil
				}
			}
			for i, n := range names {
				if i > 0 {
					a.printf("\n")
				}
				c, err := ca.Open(h, n)
				if err != nil {
					return err
				}
				if err := a.list(c); err != nil {
					return err
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "list every CA in the home directory")
	return cmd
}

func (a *app) inspectCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "inspect [name]",
		Short: "Show the CA (or one certificate) with file paths and trust commands",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			c, err := a.open()
			if err != nil {
				return err
			}
			if len(args) == 0 {
				a.describeCA(c)
				return nil
			}
			leaf, err := c.Leaf(args[0])
			if err != nil {
				return err
			}
			a.describeLeaf(leaf)
			return nil
		},
	}
}
