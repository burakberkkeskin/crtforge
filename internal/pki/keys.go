// Package pki builds the certificates, keys and CRLs crtforge issues. It has
// no knowledge of the filesystem: everything goes in and out as Go values or
// PEM/DER bytes.
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// Algorithm is the public key algorithm of a CA hierarchy.
type Algorithm string

const (
	RSA   Algorithm = "rsa"
	ECDSA Algorithm = "ecdsa"
)

// ParseAlgorithm validates a user-supplied algorithm name.
func ParseAlgorithm(s string) (Algorithm, error) {
	switch Algorithm(s) {
	case RSA, ECDSA:
		return Algorithm(s), nil
	}
	return "", fmt.Errorf("unknown key type %q (use %q or %q)", s, RSA, ECDSA)
}

// Role decides the key size: CA keys live for years, leaf keys for months.
type Role int

const (
	RoleRoot Role = iota
	RoleIntermediate
	RoleLeaf
)

// GenerateKey creates a key for the given role.
//
//	RSA:   root 4096, intermediate 3072, leaf 2048 bits
//	ECDSA: root and intermediate P-384, leaf P-256
func GenerateKey(alg Algorithm, role Role) (crypto.Signer, error) {
	switch alg {
	case RSA:
		bits := map[Role]int{RoleRoot: 4096, RoleIntermediate: 3072, RoleLeaf: 2048}[role]
		return rsa.GenerateKey(rand.Reader, bits)
	case ECDSA:
		curve := elliptic.P384()
		if role == RoleLeaf {
			curve = elliptic.P256()
		}
		return ecdsa.GenerateKey(curve, rand.Reader)
	}
	return nil, fmt.Errorf("unknown key type %q", alg)
}

// AlgorithmOf reports the algorithm of a public key.
func AlgorithmOf(pub crypto.PublicKey) (Algorithm, error) {
	switch pub.(type) {
	case *rsa.PublicKey:
		return RSA, nil
	case *ecdsa.PublicKey:
		return ECDSA, nil
	}
	return "", fmt.Errorf("unsupported public key type %T", pub)
}

// MarshalPrivateKey encodes a key as an unencrypted PKCS #8 PEM block.
func MarshalPrivateKey(key crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParsePrivateKey reads the first private key in PEM data. It accepts PKCS #8,
// PKCS #1 (crtforge v1 root keys) and SEC 1 EC keys.
func ParsePrivateKey(data []byte) (crypto.Signer, error) {
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return nil, errors.New("no private key found in PEM data")
		}
		var (
			key any
			err error
		)
		switch block.Type {
		case "PRIVATE KEY":
			key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		case "RSA PRIVATE KEY":
			key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		case "EC PRIVATE KEY":
			key, err = x509.ParseECPrivateKey(block.Bytes)
		case "ENCRYPTED PRIVATE KEY":
			return nil, errors.New("encrypted private keys are not supported")
		default:
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", block.Type, err)
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("unsupported private key type %T", key)
		}
		return signer, nil
	}
}

// KeyMatches reports whether key is the private half of cert's public key.
func KeyMatches(cert *x509.Certificate, key crypto.Signer) bool {
	pub, ok := key.Public().(interface{ Equal(crypto.PublicKey) bool })
	return ok && pub.Equal(cert.PublicKey)
}
