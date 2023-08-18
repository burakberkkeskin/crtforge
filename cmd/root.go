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
var rootCaCnf []byte

//go:embed intermediateCACnf.templ
var intermediateCACnf []byte

//go:embed applicationCnf.templ
var applicationCnf []byte

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "crtforge",
	Short: "Be a local cert authority",
	Long: `With crtforge, you can create root, intermediate and application ca.
For example:
./crtforge crtforge crtforge.com app.crtforge.com api.crtforge.com 
`,
	Args: cobra.MinimumNArgs(2),
	Run:  rootRun,
}

func rootRun(cmd *cobra.Command, args []string) {
	appName := args[0]
	appDomains := args[1:]

	homeDirectory, err := os.UserHomeDir()
	if err != nil {
		log.Fatal("home directory couldn't find", err)
	}
	configDirectory := homeDirectory + "/.config/crtforge"
	createConfigDir(configDirectory)
	defaultCADir := createDefaultCADir(configDirectory)

	defaultCARootCACrt, defaultCARootCACnf, defaultCARootCAkey := createRootCa(defaultCADir)
	_ = defaultCARootCAkey

	defaultCAIntermediateCACrt, defaultCAIntermediateCACnf, defaultCAIntermediateCAkey := createIntermediateCa(defaultCADir, defaultCARootCACnf)

	createAppCrt(defaultCADir, defaultCAIntermediateCACnf, defaultCAIntermediateCACrt, defaultCAIntermediateCAkey, defaultCARootCACrt, appName, appDomains[0], appDomains)
}

func createConfigDir(configDir string) {
	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		err := os.MkdirAll(configDir, 0700)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func createRootCa(CaDir string) (string, string, string) {
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

func createIntermediateCa(CaDir string, rootCaCnf string) (string, string, string) {
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
	intermediateCaCnfFile := intermediateCaDir + "/intermediateCA.cnf"
	if _, err := os.Stat(intermediateCaCnfFile); os.IsNotExist(err) {
		err := os.WriteFile(intermediateCaCnfFile, intermediateCACnf, os.ModePerm)
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
			"-subj", "/C=TR/ST=Istanbul/L=Istanbul/O=Safderun/OU=Safderun Intermediate CA/CN=Safderun Intermediate CA/emailAddress=burakberkkeskin@gmail.com",
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

func createAppCrt(defaultCADir string, intermediateCaCnf string, intermediateCaCrt string, intermediateCaKey string, rootCaCrt string, appName string, commonName string, altNames []string) {
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

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.crtforge.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
