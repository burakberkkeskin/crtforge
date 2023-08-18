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

//go:embed rootCaCnf.tmpl
var rootCaCnfTmpl []byte

func CreateRootCa(CaDir string) (string, string, string) {
	// Create the default root ca folder if not exists:
	rootCaDir := CaDir + "/rootCA"

	if _, err := os.Stat(rootCaDir); os.IsNotExist(err) {
		err := os.Mkdir(rootCaDir, 0700)
		if err != nil {
			log.Fatal(err)
		}
	}

	// Create rootCA key with openssl
	rootCaKeyFile := rootCaDir + "/rootCA.key"
	if _, err := os.Stat(rootCaKeyFile); os.IsNotExist(err) {
		createRootCaKeyCmd := exec.Command("openssl", "genrsa", "-out", rootCaKeyFile, "4096")
		createRootCaKeyCmd.Dir = rootCaDir
		err = createRootCaKeyCmd.Run()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Root CA Key generated at ", rootCaKeyFile)
	}

	// Create default CA root CA cnf file
	rootCaCnf, err := prepareRootCnf(rootCaDir)
	if err != nil {
		log.Fatal("Error while creating root cnf file:", err)
	}
	rootCaCnfFile := rootCaDir + "/rootCA.cnf"
	if _, err := os.Stat(rootCaCnfFile); os.IsNotExist(err) {
		err := os.WriteFile(rootCaCnfFile, rootCaCnf, os.ModePerm)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Root CA CNF generated at ", rootCaCnfFile)
	}

	// Create default CA root CA crt file
	rootCaCrtFile := rootCaDir + "/rootCA.crt"
	if _, err := os.Stat(rootCaCrtFile); os.IsNotExist(err) {
		createRootCaCrtCmd := exec.Command(
			"openssl", "req",
			"-config", rootCaCnfFile,
			"-key", rootCaKeyFile,
			"-new", "-x509",
			"-days", "7305",
			"-sha256", "-extensions",
			"v3_ca",
			"-subj", "/C=TR/ST=Istanbul/L=Istanbul/O=Safderun/OU=Safderun ROOT CA/CN=Safderun ROOT CA/emailAddress=burakberkkeskin@gmail.com",
			"-out", rootCaCrtFile)
		createRootCaCrtCmd.Dir = rootCaDir
		err = createRootCaCrtCmd.Run()
		if err != nil {
			log.Fatal("Error while creating default ca root ca crt: ", err)
		}
		fmt.Println("Root CA crt generated at ", rootCaKeyFile)
	}

	// Create necessary files & folders
	newCertsDir := rootCaDir + "/newcerts"
	if _, err := os.Stat(newCertsDir); os.IsNotExist(err) {
		fmt.Println("newcerts folder does not exists")
		err := os.Mkdir(newCertsDir, 0755)
		if err != nil {
			log.Fatal("error while creating newcerts dir", err)
		}
	}

	indexFile := rootCaDir + "/index.txt"
	os.OpenFile(indexFile, os.O_RDONLY|os.O_CREATE, 0600)

	serialFile := rootCaDir + "/serial"
	if _, err := os.Stat(serialFile); os.IsNotExist(err) {
		file, err := os.Create(serialFile)
		if err != nil {
			log.Fatal("Error creating file:", err)
		}
		defer file.Close()
		_, err = file.WriteString("1000\n")
		if err != nil {
			log.Fatal("Error writing to file:", err)
		}
		if err != nil {
			log.Fatal(err)
		}
	}
	os.OpenFile(serialFile, os.O_RDONLY|os.O_CREATE, 0600)
	fmt.Println("Root CA initialized ")
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
