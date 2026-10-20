package pki

import (
	"reflect"
	"testing"
)

func TestParseSANs(t *testing.T) {
	tests := []struct {
		in      []string
		dns     []string
		ips     []string
		wantErr bool
	}{
		{in: []string{"App.Example.Test", "app.example.test.", "*.example.test"}, dns: []string{"app.example.test", "*.example.test"}},
		{in: []string{"localhost", "127.0.0.1", "::1", "127.0.0.1"}, dns: []string{"localhost"}, ips: []string{"127.0.0.1", "::1"}},
		{in: []string{"a.test", "A.TEST"}, dns: []string{"a.test"}},
		{in: []string{"xn--bcher-kva.test"}, dns: []string{"xn--bcher-kva.test"}},
		{in: nil, wantErr: true},
		{in: []string{""}, wantErr: true},
		{in: []string{"*.test"}, wantErr: true},
		{in: []string{"a.*.test"}, wantErr: true},
		{in: []string{"*a.example.test"}, wantErr: true},
		{in: []string{"-a.test"}, wantErr: true},
		{in: []string{"a_b.test"}, wantErr: true},
		{in: []string{"a..test"}, wantErr: true},
		{in: []string{"bücher.test"}, wantErr: true},
		{in: []string{"a b.test"}, wantErr: true},
		{in: []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.test"}, wantErr: true},
	}
	for _, tt := range tests {
		got, err := ParseSANs(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseSANs(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			continue
		}
		if tt.wantErr {
			continue
		}
		var ips []string
		for _, ip := range got.IPs {
			ips = append(ips, ip.String())
		}
		if !reflect.DeepEqual(got.DNS, tt.dns) || !reflect.DeepEqual(ips, tt.ips) {
			t.Errorf("ParseSANs(%q) = %v %v, want %v %v", tt.in, got.DNS, ips, tt.dns, tt.ips)
		}
	}
}
