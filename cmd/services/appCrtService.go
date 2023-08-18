package services

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
	"log"
	"os"
	"os/exec"
	"strings"
)

//go:embed appCnf.tmpl
var applicationCnf []byte

func CreateAppCrt(defaultCADir string, intermediateCaCnf string, intermediateCaCrt string, intermediateCaKey string, rootCaCrt string, appName string, commonName string, altNames []string) {
	// Create app directory if not exists:
	appCrtDir := defaultCADir + "/" + appName
	if _, err := os.Stat(appCrtDir); os.IsNotExist(err) {
		err := os.Mkdir(appCrtDir, 0700)
		if err != nil {
			log.Fatal(err)
		}
	}

	// Create app key with openssl
	applicationKeyFile := appCrtDir + "/" + appName + ".key"
	if _, err := os.Stat(applicationKeyFile); os.IsNotExist(err) {
		createAppKeyCmd := exec.Command("openssl", "genpkey", "-algorithm", "RSA", "-out", applicationKeyFile)
		createAppKeyCmd.Dir = appCrtDir
		err = createAppKeyCmd.Run()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("App Key generated at ", applicationKeyFile)
	}

	// Create app cnf file
	appCnf, err := prepareAppCnf(appName, commonName, altNames)
	if err != nil {
		fmt.Println("Error while creating app cnf file:", err)
		return
	}

	applicationCnfFile := appCrtDir + "/" + appName + ".cnf"
	if _, err := os.Stat(applicationCnfFile); os.IsNotExist(err) {
		err := os.WriteFile(applicationCnfFile, appCnf, os.ModePerm)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("App CNF generated at ", applicationCnfFile)
	}

	// Create default CA App csr file
	applicationCsrFile := appCrtDir + "/" + appName + ".csr"
	if _, err := os.Stat(applicationCsrFile); os.IsNotExist(err) {
		createAppCsrCmd := exec.Command(
			"openssl", "req", "-new",
			"-key", applicationKeyFile,
			"-config", applicationCnfFile,
			"-out", applicationCsrFile,
		)
		createAppCsrCmd.Dir = appCrtDir
		err = createAppCsrCmd.Run()
		if err != nil {
			log.Fatal("Error while creating app csr: ", err)
		}
		fmt.Println("App csr generated at ", applicationCsrFile)
	}

	// Create default CA intermediate CA crt file
	applicationCrtFile := appCrtDir + "/" + appName + ".crt"
	if _, err := os.Stat(applicationCrtFile); os.IsNotExist(err) {
		createAppCrtCmd := exec.Command(
			"openssl", "x509", "-req",
			"-in", applicationCsrFile,
			"-CA", intermediateCaCrt,
			"-CAkey", intermediateCaKey,
			"-CAcreateserial",
			"-days", "365",
			"-extensions", "v3_ext",
			"-extfile", applicationCnfFile,
			"-out", applicationCrtFile,
		)
		createAppCrtCmd.Dir = appCrtDir
		err = createAppCrtCmd.Run()
		if err != nil {
			log.Fatal("Error while creating app crt: ", err)
		}
		fmt.Println("App CRT generated at ", applicationCrtFile)
	}

	// Create fullchain cert file.
	rootCaCrtContent, err := os.ReadFile(rootCaCrt)
	if err != nil {
		fmt.Println("Error reading file root ca:", err)
		return
	}

	intermediateCaCrtContent, err := os.ReadFile(intermediateCaCrt)
	if err != nil {
		fmt.Println("Error reading file b:", err)
		return
	}

	appCrtContent, err := os.ReadFile(applicationCrtFile)
	if err != nil {
		fmt.Println("Error reading file b:", err)
		return
	}

	appFullchainCrtFile := appCrtDir + "/fullchain.crt"
	if _, err := os.Stat(appFullchainCrtFile); os.IsNotExist(err) {
		file, err := os.Create(appFullchainCrtFile)
		if err != nil {
			log.Fatal("Error creating fullchain file:", err)
		}
		defer file.Close()

		fullchainCrtFile, err := os.OpenFile(appFullchainCrtFile, os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			log.Fatal("Error opening file fullchain crt file:", err)
		}
		defer fullchainCrtFile.Close()

		_, err = fullchainCrtFile.Write(appCrtContent)
		if err != nil {
			log.Fatal("Error writing crt to file fullchain crt:", err)
		}

		_, err = fullchainCrtFile.Write(intermediateCaCrtContent)
		if err != nil {
			log.Fatal("Error writing intermediate ca to file fullchain crt:", err)
		}

		_, err = fullchainCrtFile.Write(rootCaCrtContent)
		if err != nil {
			log.Fatal("Error writing root ca crt to file fullchain crt:", err)
		}
		fmt.Println("App Fullchain crt generated at ", applicationCrtFile)
	}

	fmt.Println("App Cert Generated Successfully.")
}

func prepareAppCnf(appName string, commonName string, altNames []string) ([]byte, error) {
	tmpl, err := template.New("applicationCnf").Parse(string(applicationCnf))
	if err != nil {
		return nil, err
	}
	vars := make(map[string]interface{})
	vars["appName"] = appName
	vars["commonName"] = commonName
	vars["altNames"] = generateAltNames(altNames)

	var output bytes.Buffer
	if err := tmpl.Execute(&output, vars); err != nil {
		return nil, err
	}

	return output.Bytes(), nil
}

func generateAltNames(altNames []string) string {
	var dnsLines []string
	for i, altName := range altNames {
		dnsLines = append(dnsLines, fmt.Sprintf("DNS.%d = %s", i+1, altName))
	}
	return strings.Join(dnsLines, "\n")
}
