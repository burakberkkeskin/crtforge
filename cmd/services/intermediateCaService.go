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

//go:embed intermediateCaCnf.tmpl
var intermediateCACnfTmpl []byte

func CreateIntermediateCa(CaDir string, intermediateCaName string, rootCaCnf string) (string, string, string) {
	// Create intermediate ca folder
	intermediateCaDir := CaDir + "/" + intermediateCaName
	if _, err := os.Stat(intermediateCaDir); os.IsNotExist(err) {
		log.Debug("Intermediate CA dir is being created", intermediateCaDir)
		err := os.Mkdir(intermediateCaDir, 0700)
		if err != nil {
			log.Fatal("Error while creating Intermediate CA dir: ", err)
		}
		log.Debug("Intermediate CA dir generated at ", intermediateCaDir)
	} else {
		log.Debug("Intermediate CA dir already exists, skipping.")
	}

	// Create intermediate ca key file
	intermediateCaKeyFile := intermediateCaDir + "/intermediateCA.key"
	if _, err := os.Stat(intermediateCaKeyFile); os.IsNotExist(err) {
		log.Debug("Intermediate CA Key is being created.")
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

		file, err := os.Create(intermediateCaKeyFile)
		if err != nil {
			panic(err)
		}
		defer file.Close()
		err = pem.Encode(file, privKeyPEM)
		if err != nil {
			panic(err)
		}

		log.Debug("Intermediate CA Key generated at ", intermediateCaKeyFile)
	} else {
		log.Debug("Intermediate CA Key already exists, skipping.")
	}

	// Create intermediate ca cnf file

	intermediateCaCnfFile := intermediateCaDir + "/intermediateCA.cnf"
	if _, err := os.Stat(intermediateCaCnfFile); os.IsNotExist(err) {
		log.Debug("Intermediate CA Cnf being created.")
		intermediateCaCnf, err := prepareIntermediateCnf(intermediateCaDir)
		if err != nil {
			log.Fatal("Error while creating Intermediate CA Cnf from template: ", err)
		}
		err = os.WriteFile(intermediateCaCnfFile, intermediateCaCnf, os.ModePerm)
		if err != nil {
			log.Fatal("Error while writing Intermediate CA Cnf to file: ", err)
		}
		log.Debug("Intermediate CA Cnf generated at ", intermediateCaCnfFile)
	} else {
		log.Debug("Intermediate CA Cnf already exists, skipping.")
	}

	// Create intermediate ca csr file
	intermediateCaCsrFile := intermediateCaDir + "/intermediateCA.csr"
	if _, err := os.Stat(intermediateCaCsrFile); os.IsNotExist(err) {
		log.Debug("Intermediate CA Csr being created.")
		crtSubject := "/C=TR/ST=Istanbul/L=Istanbul/O=Crtforge/OU=" + intermediateCaName + "/CN=Crtforge Intermediate CA/emailAddress=crtforge@burakberk.dev"
		createIntermediateCaCsrCmd := exec.Command(
			"openssl", "req", "-nodes",
			"-config", intermediateCaCnfFile,
			"-new", "-sha256",
			"-keyout", intermediateCaKeyFile,
			"-out", intermediateCaCsrFile,
			"-subj", crtSubject,
		)
		createIntermediateCaCsrCmd.Dir = intermediateCaDir
		err = createIntermediateCaCsrCmd.Run()
		if err != nil {
			log.Fatal("Error while creating Intermediate CA Crt: ", err)
		}
		log.Debug("Intermediate CA Csr generated at ", intermediateCaCsrFile)
	} else {
		log.Debug("Intermediate CA Csr already exists, skipping.")
	}

	// Create intermediate ca crt file
	intermediateCaCrtFile := intermediateCaDir + "/intermediateCA.crt"
	if _, err := os.Stat(intermediateCaCrtFile); os.IsNotExist(err) {
		log.Debug("Intermediate CA Crt being created")
		createIntermediateCaCrtCmd := exec.Command(
			"openssl", "ca", "-batch",
			"-config", rootCaCnf,
			"-extensions", "v3_intermediate_ca",
			"-days", "3650",
			"-notext", "-md", "sha256",
			"-in", intermediateCaCsrFile,
			"-out", intermediateCaCrtFile,
		)
		createIntermediateCaCrtCmd.Dir = intermediateCaDir
		err = createIntermediateCaCrtCmd.Run()
		if err != nil {
			log.Fatal("Error while creating Intermediate CA Crt: ", err)
		}
		log.Debug("Intermediate CA Crt generated at ", intermediateCaCrtFile)
	}

	log.Debug("Intermediate CA created.")
	return intermediateCaCrtFile, intermediateCaCnfFile, intermediateCaKeyFile
}

func prepareIntermediateCnf(intermediateCaDir string) ([]byte, error) {
	tmpl, err := template.New("intermediateCaCnf").Parse(string(intermediateCACnfTmpl))
	if err != nil {
		return nil, err
	}
	vars := make(map[string]interface{})
	vars["dir"] = intermediateCaDir

	var output bytes.Buffer
	if err := tmpl.Execute(&output, vars); err != nil {
		return nil, err
	}

	return output.Bytes(), nil
}
