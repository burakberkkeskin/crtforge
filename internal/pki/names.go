package pki

import (
	"fmt"
	"net"
	"strings"
)

// SANs are the subject alternative names of a leaf certificate.
type SANs struct {
	DNS []string
	IPs []net.IP
}

// Strings returns the names in the order DNS names first, then IP addresses.
func (s SANs) Strings() []string {
	out := append([]string{}, s.DNS...)
	for _, ip := range s.IPs {
		out = append(out, ip.String())
	}
	return out
}

// ParseSANs validates host names and IP addresses given on the command line.
// DNS names are lower-cased without a trailing dot; duplicates are dropped.
func ParseSANs(args []string) (SANs, error) {
	var s SANs
	seen := map[string]bool{}
	for _, arg := range args {
		name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(arg)), ".")
		if name == "" {
			return SANs{}, fmt.Errorf("empty name")
		}
		if ip := net.ParseIP(name); ip != nil {
			if v4 := ip.To4(); v4 != nil {
				ip = v4
			}
			if !seen[ip.String()] {
				seen[ip.String()] = true
				s.IPs = append(s.IPs, ip)
			}
			continue
		}
		if err := validateDNSName(name); err != nil {
			return SANs{}, fmt.Errorf("%q: %w", arg, err)
		}
		if !seen[name] {
			seen[name] = true
			s.DNS = append(s.DNS, name)
		}
	}
	if len(s.DNS)+len(s.IPs) == 0 {
		return SANs{}, fmt.Errorf("at least one DNS name or IP address is required")
	}
	return s, nil
}

func validateDNSName(name string) error {
	if len(name) > 253 {
		return fmt.Errorf("longer than 253 characters")
	}
	labels := strings.Split(name, ".")
	for i, label := range labels {
		if label == "*" {
			if i != 0 {
				return fmt.Errorf("a wildcard is only allowed as the whole left-most label")
			}
			if len(labels) < 3 {
				return fmt.Errorf("a wildcard needs at least two labels after it (e.g. *.example.test)")
			}
			continue
		}
		if err := validateLabel(label); err != nil {
			return err
		}
	}
	return nil
}

func validateLabel(label string) error {
	if label == "" {
		return fmt.Errorf("empty label")
	}
	if len(label) > 63 {
		return fmt.Errorf("label %q longer than 63 characters", label)
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return fmt.Errorf("label %q starts or ends with a hyphen", label)
	}
	for _, r := range label {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
		case r > 127:
			return fmt.Errorf("non-ASCII name; use the punycode (xn--) form")
		default:
			return fmt.Errorf("invalid character %q", r)
		}
	}
	return nil
}
