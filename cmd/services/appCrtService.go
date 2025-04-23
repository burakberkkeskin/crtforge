package services

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"

	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"software.sslmate.com/src/go-pkcs12"
)

type CreateAppCrtOptions struct {
	// OutputDir is the output directory for created certificates
	OutputDir string
	// IntermediateCaCnf is the intermediate ca cnf file
	IntermediateCACnf string
	// IntermediateCaCrt is the intermediate ca crt file
	IntermediateCACrt string
	// IntermediateCaKey is the intermediate ca key file
	IntermediateCAKey string
	// RootCaCrt is the root ca crt file
	RootCACrt string
	// AppName is the name of the application
	AppName string
	// CommonName is the common name of the application
	CommonName string
	// AltNames is the alternative names of the application
	AltNames []string
	// P12 is the flag for creating p12 files
	P12 bool
}

func CreateAppCrt(opts CreateAppCrtOptions) {
	// Create app directory if not exists
	appCrtDir := fmt.Sprintf("%s/%s", opts.OutputDir, opts.AppName)
	if err := os.MkdirAll(appCrtDir, 0700); err != nil {
		log.Fatal("Error while creating App dir: ", err)
	}

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal("Error generating private key: ", err)
	}

	// Create app key file
	applicationKeyFile := fmt.Sprintf("%s/%s.key", appCrtDir, opts.AppName)
	keyOut, err := os.OpenFile(applicationKeyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatal("Error creating key file: ", err)
	}
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	keyOut.Close()

	// Load CA certificate and key
	caCert, caKey, err := loadCACertAndKey(opts.IntermediateCACrt, opts.IntermediateCAKey)
	if err != nil {
		log.Fatal("Error loading CA certificate and key: ", err)
	}

	// Prepare certificate template
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatal("Error generating serial number: ", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: opts.CommonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	for _, altName := range opts.AltNames {
		if ip := net.ParseIP(altName); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, altName)
		}
	}

	// Create certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, &privateKey.PublicKey, caKey)
	if err != nil {
		log.Fatal("Error creating certificate: ", err)
	}

	// Write certificate to file
	applicationCrtFile := fmt.Sprintf("%s/%s.crt", appCrtDir, opts.AppName)
	certOut, err := os.Create(applicationCrtFile)
	if err != nil {
		log.Fatal("Error creating certificate file: ", err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()

	// Create fullchain certificate file
	err = createFullchainCert(opts, applicationCrtFile, appCrtDir)
	if err != nil {
		log.Fatal("Error creating fullchain certificate: ", err)
	}

	// Conditionally create PFX file
	if opts.P12 {
		pfxOutputFile := fmt.Sprintf("%s/%s.pfx", appCrtDir, opts.AppName)
		err := createPFX(applicationKeyFile, applicationCrtFile, opts.IntermediateCACrt, opts.RootCACrt, pfxOutputFile, "changeit")
		if err != nil {
			// Use Fatalf for consistency with other error handling in this function
			log.Fatalf("Error creating PFX file: %v", err)
		}
		// Add log message about PFX creation
		log.Info("PFX file created successfully.")
		log.Info("PFX file path: ", pfxOutputFile)
	}

	log.Info("App certs created successfully.")
	log.Info("App name: ", opts.AppName)
	log.Info("Domains: ", opts.AltNames)
	log.Info("To see your cert files, please check the dir: ", appCrtDir)
}

func loadCACertAndKey(caCertFile, caKeyFile string) (*x509.Certificate, interface{}, error) {
	// Read CA certificate
	caCertPEM, err := os.ReadFile(caCertFile)
	if err != nil {
		return nil, nil, fmt.Errorf("error reading CA certificate: %v", err)
	}
	caCertBlock, _ := pem.Decode(caCertPEM)
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing CA certificate: %v", err)
	}

	// Read CA private key
	caKeyPEM, err := os.ReadFile(caKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("error reading CA private key: %v", err)
	}
	caKeyBlock, _ := pem.Decode(caKeyPEM)
	caKey, err := x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing CA private key: %v", err)
	}

	return caCert, caKey, nil
}

func createFullchainCert(opts CreateAppCrtOptions, appCertFile, appCrtDir string) error {
	// Read application certificate
	appCertPEM, err := os.ReadFile(appCertFile)
	if err != nil {
		return fmt.Errorf("error reading application certificate: %v", err)
	}

	// Read intermediate CA certificate
	intermediateCACertPEM, err := os.ReadFile(opts.IntermediateCACrt)
	if err != nil {
		return fmt.Errorf("error reading intermediate CA certificate: %v", err)
	}

	// Read root CA certificate
	rootCACertPEM, err := os.ReadFile(opts.RootCACrt)
	if err != nil {
		return fmt.Errorf("error reading root CA certificate: %v", err)
	}

	// Create fullchain certificate file
	fullchainFile := fmt.Sprintf("%s/fullchain.crt", appCrtDir)
	out, err := os.Create(fullchainFile)
	if err != nil {
		return fmt.Errorf("error creating fullchain certificate file: %v", err)
	}
	defer out.Close()

	// Write certificates to fullchain file
	out.Write(appCertPEM)
	out.Write(intermediateCACertPEM)
	out.Write(rootCACertPEM)

	log.Debug("Fullchain certificate created at ", fullchainFile)
	return nil
}

func createPFX(privateKeyFile, certificateFile, intermediateCACertFile, rootCACertFile, pfxOutputFile, password string) error {
	// Read and parse the private key
	keyPEM, err := os.ReadFile(privateKeyFile)
	if err != nil {
		return fmt.Errorf("failed to read private key file: %v", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return fmt.Errorf("failed to decode private key PEM")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %v", err)
	}

	// Read and parse the certificate
	certPEM, err := os.ReadFile(certificateFile)
	if err != nil {
		return fmt.Errorf("failed to read certificate file: %v", err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return fmt.Errorf("failed to decode certificate PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %v", err)
	}

	// Read and parse the intermediate CA certificate
	intermediatePEM, err := os.ReadFile(intermediateCACertFile)
	if err != nil {
		return fmt.Errorf("failed to read intermediate CA certificate file: %v", err)
	}
	intermediateBlock, _ := pem.Decode(intermediatePEM)
	if intermediateBlock == nil {
		return fmt.Errorf("failed to decode intermediate CA certificate PEM")
	}
	intermediateCert, err := x509.ParseCertificate(intermediateBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse intermediate CA certificate: %v", err)
	}

	// Read and parse the root CA certificate
	rootPEM, err := os.ReadFile(rootCACertFile)
	if err != nil {
		return fmt.Errorf("failed to read root CA certificate file: %v", err)
	}
	rootBlock, _ := pem.Decode(rootPEM)
	if rootBlock == nil {
		return fmt.Errorf("failed to decode root CA certificate PEM")
	}
	rootCert, err := x509.ParseCertificate(rootBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse root CA certificate: %v", err)
	}

	// Create a CA certificates chain
	caCerts := []*x509.Certificate{intermediateCert, rootCert}

	// Use Modern encoder to create PKCS#12 data with strong encryption
	pfxData, err := pkcs12.Modern.Encode(privateKey, cert, caCerts, password)
	if err != nil {
		return fmt.Errorf("failed to create PKCS#12 data: %v", err)
	}

	// Write PKCS#12 data to file
	err = os.WriteFile(pfxOutputFile, pfxData, 0600)
	if err != nil {
		return fmt.Errorf("failed to write PKCS#12 file: %v", err)
	}

	return nil
}
