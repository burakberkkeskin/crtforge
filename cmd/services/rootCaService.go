package services

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"html/template"
	"os"
	"os/exec"

	log "github.com/sirupsen/logrus"
)

//go:embed rootCaCnf.tmpl
var rootCaCnfTmpl []byte

type CreateRootCAOptions struct {
	// ConfigDirectory is the config directory for crtforge
	ConfigDirectory string
	// RootCaName is the name of the root ca
	RootCAName string
	// CountryName is short hand name of the country
	CountryName string
	// StateOrProvinceName is the name of the country/state in the country
	StateOrProvinceName string
	// LocalityName
	LocalityName string
	// EmailAddress is the email address of the user
	EmailAddress string
	// BasicConstraints
	BasicConstraints string
}

func CreateRootCa(opts CreateRootCAOptions) (string, string, string) {
	// Create the default root ca folder if not exists:
	rootCaDir := opts.ConfigDirectory + "/rootCA"
	if _, err := os.Stat(rootCaDir); os.IsNotExist(err) {
		log.Debug("Root CA dir is being created", rootCaDir)
		err := os.Mkdir(rootCaDir, 0700)
		if err != nil {
			log.Fatal("Error while creating Root CA dir: ", err)
		}
		log.Debug("Root CA dir generated at ", rootCaDir)
	} else {
		log.Debug("Root CA dir already exists, skipping.")
	}

	// Create rootCA key
	rootCaKeyFile := rootCaDir + "/rootCA.key"
	if _, err := os.Stat(rootCaKeyFile); os.IsNotExist(err) {
		log.Debug("Root CA Key is being created.")
		caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			log.Error(err)
		}
		// Encode the private key to PEM format
		privKeyBytes := x509.MarshalPKCS1PrivateKey(caPrivKey)
		privKeyPEM := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privKeyBytes,
		}
		file, err := os.Create(rootCaKeyFile)
		if err != nil {
			panic(err)
		}
		defer file.Close()
		err = pem.Encode(file, privKeyPEM)
		if err != nil {
			panic(err)
		}
		log.Debug("Root CA Key generated at ", rootCaKeyFile)
	} else {
		log.Debug("Root CA Key already exists, skipping.")
	}

	// Create default CA root CA cnf file
	rootCaCnfFile := rootCaDir + "/rootCA.cnf"
	if _, err := os.Stat(rootCaCnfFile); os.IsNotExist(err) {
		log.Debug("Root CA Cnf being created.")
		rootCaCnf, err := prepareRootCnf(rootCaDir, opts)
		if err != nil {
			log.Fatal("Error while creating Root CA Cnf from template: ", err)
		}
		err = os.WriteFile(rootCaCnfFile, rootCaCnf, os.ModePerm)
		if err != nil {
			log.Fatal("Error while writing Root CA Cnf to file: ", err)
		}
		log.Debug("Root CA Cnf generated at ", rootCaCnfFile)
	} else {
		log.Debug("Root CA Cnf already exists, skipping.")
	}

	// Create default CA root CA crt file
	rootCaCrtFile := rootCaDir + "/rootCA.crt"
	if _, err := os.Stat(rootCaCrtFile); os.IsNotExist(err) {
		log.Debug("Root CA Crt being created.")
		crtSubject := "/C=" + opts.CountryName + "/ST=" + opts.StateOrProvinceName + "/L=" + opts.LocalityName + "/O=Crtforge/OU=" + opts.RootCAName + "/CN=Crtforge Root CA/emailAddress=" + opts.EmailAddress
		createRootCaCrtCmd := exec.Command(
			"openssl", "req",
			"-config", rootCaCnfFile,
			"-key", rootCaKeyFile,
			"-new", "-x509",
			"-days", "7305",
			"-sha256", "-extensions",
			"v3_ca",
			"-subj", crtSubject,
			"-out", rootCaCrtFile)
		createRootCaCrtCmd.Dir = rootCaDir
		err = createRootCaCrtCmd.Run()
		if err != nil {
			log.Fatal("Error while creating Root CA Crt: ", err)
		}
		log.Debug("Root CA Crt generated at ", rootCaKeyFile)
	} else {
		log.Debug("Root CA Crt already exists, skipping.")
	}

	// Create necessary files & folders
	newCertsDir := rootCaDir + "/newcerts"
	if _, err := os.Stat(newCertsDir); os.IsNotExist(err) {
		log.Debug("Root CA newcerts dir being created")
		err := os.Mkdir(newCertsDir, 0755)
		if err != nil {
			log.Fatal("Error while creating newcerts dir: ", err)
		}
		log.Debug("Root CA newcerts dir generated at", newCertsDir)
	} else {
		log.Debug("Root CA newcerts dir already exists, skipping.")

	}

	indexFile := rootCaDir + "/index.txt"
	if _, err := os.Stat(indexFile); os.IsNotExist(err) {
		log.Debug("Root CA index file being created")
		os.OpenFile(indexFile, os.O_RDONLY|os.O_CREATE, 0600)
		log.Debug("Root CA index file generated at", indexFile)
	} else {
		log.Debug("Root CA index file  already exists, skipping.")
	}

	serialFile := rootCaDir + "/serial"
	if _, err := os.Stat(serialFile); os.IsNotExist(err) {
		log.Debug("Root CA serial file being created")
		file, err := os.Create(serialFile)
		if err != nil {
			log.Fatal("Error while creating the serial file:", err)
		}
		defer file.Close()
		_, err = file.WriteString("1000\n")
		if err != nil {
			log.Fatal("Error while writing to the serial file:", err)
		}
		log.Debug("Root CA serial file generated at", serialFile)
	} else {
		log.Debug("Root CA serial file  already exists, skipping.")
	}

	os.OpenFile(serialFile, os.O_RDONLY|os.O_CREATE, 0600)
	log.Debug("Root CA created.")
	return rootCaCrtFile, rootCaCnfFile, rootCaKeyFile
}

func prepareRootCnf(rootCaDir string, opts CreateRootCAOptions) ([]byte, error) {
	tmpl, err := template.New("rootCaCnf").Parse(string(rootCaCnfTmpl))
	if err != nil {
		return nil, err
	}
	vars := make(map[string]interface{})
	vars["dir"] = rootCaDir
	vars["countryName"] = opts.CountryName
	vars["stateOrProvinceName"] = opts.StateOrProvinceName
	vars["localityName"] = opts.LocalityName
	vars["emailAddress"] = opts.EmailAddress
	vars["basicConstr"] = opts.BasicConstraints

	var output bytes.Buffer
	if err := tmpl.Execute(&output, vars); err != nil {
		return nil, err
	}

	return output.Bytes(), nil
}
