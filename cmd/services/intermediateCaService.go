package services

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
	"log"
	"os"
	"os/exec"
)

//go:embed intermediateCaCnf.tmpl
var intermediateCACnfTmpl []byte

func CreateIntermediateCa(CaDir string, rootCaCnf string) (string, string, string) {
	// Create intermediate ca folder
	intermediateCaDir := CaDir + "/intermediateCA"
	if _, err := os.Stat(intermediateCaDir); os.IsNotExist(err) {
		err := os.Mkdir(intermediateCaDir, 0700)
		if err != nil {
			log.Fatal(err)
		}
	}

	// Create intermediate ca key file
	intermediateCaKeyFile := intermediateCaDir + "/intermediateCA.key"
	if _, err := os.Stat(intermediateCaKeyFile); os.IsNotExist(err) {
		createIntermediateCaKeyCmd := exec.Command("openssl", "genrsa", "-out", intermediateCaKeyFile, "4096")
		createIntermediateCaKeyCmd.Dir = intermediateCaDir
		err = createIntermediateCaKeyCmd.Run()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Intermediate CA Key generated at ", intermediateCaKeyFile)
	}

	// Create intermediate ca cnf file
	intermediateCaCnf, err := prepareIntermediateCnf(intermediateCaDir)
	if err != nil {
		log.Fatal("Error while creating intermediate cnf file:", err)
	}
	intermediateCaCnfFile := intermediateCaDir + "/intermediateCA.cnf"
	if _, err := os.Stat(intermediateCaCnfFile); os.IsNotExist(err) {
		err := os.WriteFile(intermediateCaCnfFile, intermediateCaCnf, os.ModePerm)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Intermediate CA CNF generated at ", intermediateCaCnfFile)
	}

	// Create intermediate ca csr file
	intermediateCaCsrFile := intermediateCaDir + "/intermediateCA.csr"
	if _, err := os.Stat(intermediateCaCsrFile); os.IsNotExist(err) {
		createIntermediateCaCsrCmd := exec.Command(
			"openssl", "req", "-nodes",
			"-config", intermediateCaCnfFile,
			"-new", "-sha256",
			"-keyout", intermediateCaKeyFile,
			"-out", intermediateCaCsrFile,
			"-subj", "/C=TR/ST=Istanbul/L=Istanbul/O=Crtforge/OU=Crtforge Intermediate CA/CN=Crtforge Intermediate CA/emailAddress=crtforge@burakberk.dev",
		)
		createIntermediateCaCsrCmd.Dir = intermediateCaDir
		err = createIntermediateCaCsrCmd.Run()
		if err != nil {
			log.Fatal("Error while creating default ca intermediate ca csr: ", err)
		}
		fmt.Println("Intermediate CA CSR generated at ", intermediateCaCsrFile)
	}

	// Create intermediate ca crt file
	intermediateCaCrtFile := intermediateCaDir + "/intermediateCA.crt"
	if _, err := os.Stat(intermediateCaCrtFile); os.IsNotExist(err) {
		fmt.Println("Creating intermediate crt file")
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
			log.Fatal("Error while creating default ca intermediate ca crt: ", err)
		}
		fmt.Println("Intermediate CA CRT generated at ", intermediateCaCnfFile)
	}

	fmt.Println("Intermediate CA initialized successfully.")
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
