/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"bytes"
	_ "embed"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"text/template"

	"github.com/spf13/cobra"
)

//go:embed rootCACnf.templ
var defaultCARootCACnf []byte

//go:embed intermediateCACnf.templ
var defaultCAIntermediateCACnf []byte

//go:embed applicationCnf.templ
var applicationCnf []byte

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "crtForge",
	Short: "Be a local cert authority",
	Long: `With crtForge, you can create root, intermediate and application ca.
For example:
./crtForge --root "Safderun Root"
`,
	Run: rootRun,
}

func rootRun(cmd *cobra.Command, args []string) {
	fmt.Println("Hello, crtForge!")

	homeDirectory, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}
	configDirectory := homeDirectory + "/.config/crtForge"
	createConfigDir(configDirectory)
	defaultCADir := createDefaultCADir(configDirectory)

	fmt.Println("Home directory: ", homeDirectory)
	fmt.Println("Config directory: ", configDirectory)

	defaultCARootCACrt, defaultCARootCACnf, defaultCARootCAkey := createDefaultRootCA(defaultCADir)
	if defaultCARootCACrt != "" && defaultCARootCAkey != "" {
		// The variable is used here, but the condition has no impact on the logic
		fmt.Println("Using the variable:", defaultCARootCACrt)
	}

	defaultCAIntermediateCACrt, defaultCAIntermediateCACnf, defaultCAIntermediateCAkey := createDefaultIntermediateCACert(defaultCADir, defaultCARootCACnf)
	if defaultCAIntermediateCACrt != "" && defaultCAIntermediateCAkey != "" {
		// The variable is used here, but the condition has no impact on the logic
		fmt.Println("Using the variable:", defaultCARootCACrt)
	}

	createDefaultApplicationCrt(defaultCADir, defaultCAIntermediateCACnf, defaultCAIntermediateCACrt, defaultCAIntermediateCAkey, defaultCARootCACrt, "crtForge", "crtforge.com", []string{"crtforge.com", "app.crtforge.com"})
}

func createConfigDir(configDir string) {
	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		err := os.MkdirAll(configDir, 0700)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func createDefaultRootCA(defaultCADir string) (string, string, string) {
	// Create the default root ca folder if not exists:
	defaultCARootCADir := defaultCADir + "/rootCA"

	if _, err := os.Stat(defaultCARootCADir); os.IsNotExist(err) {
		err := os.Mkdir(defaultCARootCADir, 0700)
		if err != nil {
			log.Fatal(err)
		}
	}

	// Create rootCA key with openssl
	defaultCARootCAKeyFile := defaultCARootCADir + "/rootCA.key"
	if _, err := os.Stat(defaultCARootCAKeyFile); os.IsNotExist(err) {
		createRootCaKeyCmd := exec.Command("openssl", "genrsa", "-aes256", "-out", defaultCARootCAKeyFile, "4096")
		createRootCaKeyCmd.Dir = defaultCARootCADir
		err = createRootCaKeyCmd.Run()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Root CA Key generated at ", defaultCARootCAKeyFile)
	}

	// Create default CA root CA cnf file
	defaultCARootCnfFile := defaultCARootCADir + "/rootCA.cnf"
	if _, err := os.Stat(defaultCARootCnfFile); os.IsNotExist(err) {
		err := os.WriteFile(defaultCARootCnfFile, defaultCARootCACnf, os.ModePerm)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Root CA CNF generated at ", defaultCARootCnfFile)
	}

	// Create default CA root CA crt file
	defaultCARootCrtFile := defaultCARootCADir + "/rootCA.crt"
	if _, err := os.Stat(defaultCARootCrtFile); os.IsNotExist(err) {
		createRootCaCrtCmd := exec.Command(
			"openssl", "req",
			"-config", defaultCARootCnfFile,
			"-key", defaultCARootCAKeyFile,
			"-new", "-x509",
			"-days", "7305",
			"-sha256", "-extensions",
			"v3_ca",
			"-subj", "/C=TR/ST=Istanbul/L=Istanbul/O=Safderun/OU=Safderun ROOT CA/CN=Safderun ROOT CA/emailAddress=burakberkkeskin@gmail.com",
			"-out", defaultCARootCrtFile)
		createRootCaCrtCmd.Dir = defaultCARootCADir
		err = createRootCaCrtCmd.Run()
		if err != nil {
			log.Fatal("Error while creating default ca root ca crt: ", err)
		}
		fmt.Println("Root CA crt generated at ", defaultCARootCAKeyFile)
	}

	// Create necessary files & folders
	newCertDir := defaultCARootCADir + "/newcerts"
	if _, err := os.Stat(newCertDir); os.IsNotExist(err) {
		fmt.Println("newcerts folder does not exists")
		err := os.Mkdir(newCertDir, 0755)
		if err != nil {
			log.Fatal("error while creating newcert dir", err)
		}
	}

	indexFile := defaultCARootCADir + "/index.txt"
	os.OpenFile(indexFile, os.O_RDONLY|os.O_CREATE, 0600)

	serialFile := defaultCARootCADir + "/serial"
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
	return defaultCARootCrtFile, defaultCARootCnfFile, defaultCARootCAKeyFile
}

func createDefaultIntermediateCACert(defaultCADir string, defaultCARootCACnf string) (string, string, string) {
	// Create the default intermediate ca folder if not exists:
	defaultCAIntermediateCADir := defaultCADir + "/intermediateCA"
	if _, err := os.Stat(defaultCAIntermediateCADir); os.IsNotExist(err) {
		err := os.Mkdir(defaultCAIntermediateCADir, 0700)
		if err != nil {
			log.Fatal(err)
		}
	}

	// Create intermediate key with openssl
	defaultCAIntermediateCAKeyFile := defaultCAIntermediateCADir + "/intermediateCA.key"
	if _, err := os.Stat(defaultCAIntermediateCAKeyFile); os.IsNotExist(err) {
		createIntermediateCaKeyCmd := exec.Command("openssl", "genrsa", "-aes256", "-out", defaultCAIntermediateCAKeyFile, "4096")
		createIntermediateCaKeyCmd.Dir = defaultCAIntermediateCADir
		err = createIntermediateCaKeyCmd.Run()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Intermediate CA Key generated at ", defaultCAIntermediateCAKeyFile)
	}

	// Create default CA intermediate CA cnf file
	defaultCAIntermediateCnfFile := defaultCAIntermediateCADir + "/intermediateCA.cnf"
	if _, err := os.Stat(defaultCAIntermediateCnfFile); os.IsNotExist(err) {
		err := os.WriteFile(defaultCAIntermediateCnfFile, defaultCAIntermediateCACnf, os.ModePerm)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Intermediate CA CNF generated at ", defaultCAIntermediateCnfFile)
	}

	// Create default CA intermediate CA csr file
	defaultCAIntermediateCsrFile := defaultCAIntermediateCADir + "/intermediateCA.csr"
	if _, err := os.Stat(defaultCAIntermediateCsrFile); os.IsNotExist(err) {
		createIntermediateCaCsrCmd := exec.Command(
			"openssl", "req",
			"-config", defaultCAIntermediateCnfFile,
			"-new", "-sha256",
			"-keyout", defaultCAIntermediateCAKeyFile,
			"-out", defaultCAIntermediateCsrFile,
			"-subj", "/C=TR/ST=Istanbul/L=Istanbul/O=Safderun/OU=Safderun Intermediate CA/CN=Safderun Intermediate CA/emailAddress=burakberkkeskin@gmail.com",
		)
		createIntermediateCaCsrCmd.Dir = defaultCAIntermediateCADir
		err = createIntermediateCaCsrCmd.Run()
		if err != nil {
			log.Fatal("Error while creating default ca intermediate ca csr: ", err)
		}
		fmt.Println("Intermediate CA CSR generated at ", defaultCAIntermediateCnfFile)
	}

	// Create default CA intermediate CA crt file
	defaultCAIntermediateCrtFile := defaultCAIntermediateCADir + "/intermediateCA.crt"
	if _, err := os.Stat(defaultCAIntermediateCrtFile); os.IsNotExist(err) {
		fmt.Println("Creating intermediate crt file")
		createIntermediateCaCrtCmd := exec.Command(
			"openssl", "ca", "-batch",
			"-config", defaultCARootCACnf,
			"-extensions", "v3_intermediate_ca",
			"-days", "3650",
			"-notext", "-md", "sha256",
			"-in", defaultCAIntermediateCsrFile,
			"-out", defaultCAIntermediateCrtFile,
		)
		createIntermediateCaCrtCmd.Dir = defaultCAIntermediateCADir
		err = createIntermediateCaCrtCmd.Run()
		if err != nil {
			log.Fatal("Error while creating default ca intermediate ca crt: ", err)
		}
		fmt.Println("Intermediate CA CRT generated at ", defaultCAIntermediateCnfFile)
	}

	fmt.Println("Intermediate CA initialized successfully.")
	return defaultCAIntermediateCrtFile, defaultCAIntermediateCnfFile, defaultCAIntermediateCAKeyFile
}

func createDefaultApplicationCrt(defaultCADir string, defaultCAIntermediateCaCnf string, defaultCAIntermediateCaCrt string, defaultCAIntermediateCaKey string, defaultCARootCACrt string, appName string, commonName string, altNames []string) {
	// Create the default application  folder if not exists:
	defaultCAApplicationCrtDir := defaultCADir + "/" + appName
	if _, err := os.Stat(defaultCAApplicationCrtDir); os.IsNotExist(err) {
		err := os.Mkdir(defaultCAApplicationCrtDir, 0700)
		if err != nil {
			log.Fatal(err)
		}
	}

	// Create app key with openssl
	defaultCAApplicationKeyFile := defaultCAApplicationCrtDir + "/" + appName + ".key"
	if _, err := os.Stat(defaultCAApplicationKeyFile); os.IsNotExist(err) {
		createIntermediateCaKeyCmd := exec.Command("openssl", "genpkey", "-algorithm", "RSA", "-out", defaultCAApplicationKeyFile)
		createIntermediateCaKeyCmd.Dir = defaultCAApplicationCrtDir
		err = createIntermediateCaKeyCmd.Run()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Application Key generated at ", defaultCAApplicationKeyFile)
	}

	appCnf, err := prepareAppCnf(appName, commonName, altNames)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	// Create default CA App cnf file
	defaultCAApplicationCnfFile := defaultCAApplicationCrtDir + "/" + appName + ".cnf"
	if _, err := os.Stat(defaultCAApplicationCnfFile); os.IsNotExist(err) {
		err := os.WriteFile(defaultCAApplicationCnfFile, appCnf, os.ModePerm)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("App CNF generated at ", defaultCAApplicationCnfFile)
	}

	// Create default CA App csr file
	defaultCAApplicationCsrFile := defaultCAApplicationCrtDir + "/" + appName + ".csr"
	if _, err := os.Stat(defaultCAApplicationCsrFile); os.IsNotExist(err) {
		createIntermediateCaCsrCmd := exec.Command(
			"openssl", "req",
			"-key", defaultCAApplicationKeyFile,
			"-config", defaultCAApplicationCnfFile,
			"-out", defaultCAApplicationCsrFile,
		)
		createIntermediateCaCsrCmd.Dir = defaultCAApplicationCrtDir
		err = createIntermediateCaCsrCmd.Run()
		if err != nil {
			log.Fatal("Error while creating app csr: ", err)
		}
		fmt.Println("App csr generated at ", defaultCAApplicationCsrFile)
	}

	// Create default CA intermediate CA crt file
	defaultCAApplicationCrtFile := defaultCAApplicationCrtDir + "/" + appName + ".crt"
	if _, err := os.Stat(defaultCAApplicationCrtFile); os.IsNotExist(err) {
		createIntermediateCaCrtCmd := exec.Command(
			"openssl", "x509", "-req",
			"-in", defaultCAApplicationCsrFile,
			"-CA", defaultCAIntermediateCaCrt,
			"-CAkey", defaultCAIntermediateCaKey,
			"-CAcreateserial",
			"-days", "365",
			"-extensions", "v3_ext",
			"-extfile", defaultCAApplicationCnfFile,
			"-out", defaultCAApplicationCrtFile,
		)
		createIntermediateCaCrtCmd.Dir = defaultCAApplicationCrtDir
		err = createIntermediateCaCrtCmd.Run()
		if err != nil {
			log.Fatal("Error while creating app crt: ", err)
		}
		fmt.Println("App CRT generated at ", defaultCAApplicationCrtFile)
	}

	// Create fullchain cert file.
	rootCACrt, err := os.ReadFile(defaultCARootCACrt)
	if err != nil {
		fmt.Println("Error reading file root ca:", err)
		return
	}

	intermediateCaCrt, err := os.ReadFile(defaultCAIntermediateCaCrt)
	if err != nil {
		fmt.Println("Error reading file b:", err)
		return
	}

	appCrt, err := os.ReadFile(defaultCAApplicationCrtFile)
	if err != nil {
		fmt.Println("Error reading file b:", err)
		return
	}

	defaultCAApplicationFullchainCrtFile := defaultCAApplicationCrtDir + "/fullchain.crt"
	if _, err := os.Stat(defaultCAApplicationFullchainCrtFile); os.IsNotExist(err) {
		file, err := os.Create(defaultCAApplicationFullchainCrtFile)
		if err != nil {
			log.Fatal("Error creating fullchain file:", err)
		}
		defer file.Close()

		fullchainCrtFile, err := os.OpenFile(defaultCAApplicationFullchainCrtFile, os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			log.Fatal("Error opening file fullchain crt file:", err)
		}
		defer fullchainCrtFile.Close()

		_, err = fullchainCrtFile.Write(appCrt)
		if err != nil {
			log.Fatal("Error writing crt to file fullchain crt:", err)
		}

		_, err = fullchainCrtFile.Write(intermediateCaCrt)
		if err != nil {
			log.Fatal("Error writing intermediate ca to file fullchain crt:", err)
		}

		_, err = fullchainCrtFile.Write(rootCACrt)
		if err != nil {
			log.Fatal("Error writing root ca crt to file fullchain crt:", err)
		}
		fmt.Println("App Fullchain crt generated at ", defaultCAApplicationCrtFile)
	}

	fmt.Println("App Cert Generated Successfully.")
}

func prepareAppCnf(appName string, commonName string, altNames []string) ([]byte, error) {
	tmpl, err := template.New("applicationCnf").Parse(string(applicationCnf))
	if err != nil {
		return nil, err
	}
	vars := make(map[string]interface{})
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

func createDefaultCADir(configDir string) string {
	defaultCADir := configDir + "/default"
	if _, err := os.Stat(defaultCADir); os.IsNotExist(err) {
		err := os.Mkdir(defaultCADir, 0700)
		if err != nil {
			log.Fatal(err)
		}
	}
	return defaultCADir
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.crtForge.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
