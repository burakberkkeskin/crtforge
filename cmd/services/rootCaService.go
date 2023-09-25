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

func CreateRootCa(CaDir string) (string, string, string) {
	// Create the default root ca folder if not exists:
	rootCaDir := CaDir + "/rootCA"
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

	// Create rootCA key with openssl
	rootCaKeyFile := rootCaDir + "/rootCA.key"
	if _, err := os.Stat(rootCaKeyFile); os.IsNotExist(err) {
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
	} else {
		log.Debug("Root CA Key already exists, skipping.")
	}

	// Create default CA root CA cnf file
	rootCaCnfFile := rootCaDir + "/rootCA.cnf"
	if _, err := os.Stat(rootCaCnfFile); os.IsNotExist(err) {
		log.Debug("Root CA Cnf being created.")
		rootCaCnf, err := prepareRootCnf(rootCaDir)
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
		createRootCaCrtCmd := exec.Command(
			"openssl", "req",
			"-config", rootCaCnfFile,
			"-key", rootCaKeyFile,
			"-new", "-x509",
			"-days", "7305",
			"-sha256", "-extensions",
			"v3_ca",
			"-subj", "/C=TR/ST=Istanbul/L=Istanbul/O=Crtforge/OU=Crtforge ROOT CA/CN=Crtforge ROOT CA/emailAddress=crtforge@burakberk.dev",
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

func prepareRootCnf(rootCaDir string) ([]byte, error) {
	tmpl, err := template.New("rootCaCnf").Parse(string(rootCaCnfTmpl))
	if err != nil {
		return nil, err
	}
	vars := make(map[string]interface{})
	vars["dir"] = rootCaDir

	var output bytes.Buffer
	if err := tmpl.Execute(&output, vars); err != nil {
		return nil, err
	}

	return output.Bytes(), nil
}
