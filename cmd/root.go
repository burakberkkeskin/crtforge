/*
Copyright © 2023 NAME HERE crtforge@burakberk.dev
*/
package cmd

import (
	"crtforge/cmd/services"
	_ "embed"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/spf13/cobra"
)

// Cli flags
var caName string
var outputDir string
var intermediateCaName string
var trustRootCrt bool
var pfx bool
var emailAddress string
var countryName string
var stateOrProvinceName string
var localityName string
var basicConstraints string
var renew bool

var version = "v1.0.0"
var commitId = "abcd"

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:     "crtforge webapp app.example.com",
	Short:   "Be a local cert authority",
	Long:    `With crtforge, you can create root, intermediate and application ca.`,
	Version: version + " " + commitId,
	PreRun:  toggleDebug,
	Run:     rootRun,
}

func rootRun(cmd *cobra.Command, args []string) {
	if len(args) == 0 {
		log.Error("No argument provided.")
		log.Fatal("Please run crtforge --help for example usage.")
	}

	appName := args[0]
	appDomains := args[1:]

	homeDirectory, err := os.UserHomeDir()
	if err != nil {
		log.Fatal("home directory couldn't find", err)
	}
	configDirectory := homeDirectory + "/.config/crtforge"
	createConfigDir(configDirectory)
	defaultCADir := services.CreateCaDir(configDirectory, caName)

	var rootCrt, rootCnf, rootKey string
	var interCrt, interCnf, interKey string

	if renew {
		// Use existing CA certificates if renewing leaf certificate
		rootCrt = defaultCADir + "/rootCA/rootCA.crt"
		rootCnf = defaultCADir + "/rootCA/rootCA.cnf"
		rootKey = defaultCADir + "/rootCA/rootCA.key"

		interCrt = defaultCADir + "/" + intermediateCaName + "/intermediateCA.crt"
		interCnf = defaultCADir + "/" + intermediateCaName + "/intermediateCA.cnf"
		interKey = defaultCADir + "/" + intermediateCaName + "/intermediateCA.key"

		if _, err := os.Stat(rootCrt); os.IsNotExist(err) {
			log.Fatal("Cannot renew: Root CA certificate not found. Run without --renew to create them.")
		}
		if _, err := os.Stat(interCrt); os.IsNotExist(err) {
			log.Fatal("Cannot renew: Intermediate CA certificate not found. Run without --renew to create them.")
		}
	} else {
		rootCrt, rootCnf, rootKey = services.CreateRootCa(services.CreateRootCAOptions{
			ConfigDirectory:     defaultCADir,
			EmailAddress:        emailAddress,
			StateOrProvinceName: stateOrProvinceName,
			LocalityName:        localityName,
			CountryName:         countryName,
			BasicConstraints:    basicConstraints,
		})

		if trustRootCrt {
			services.TrustCrt(rootCrt)
		}

		intermediateCA := services.CreateIntermediateCa(services.CreateIntermediateCAOptions{
			ConfigDirectory:     defaultCADir,
			RootCACnf:           rootCnf,
			IntermediateCAName:  intermediateCaName,
			EmailAddress:        emailAddress,
			StateOrProvinceName: stateOrProvinceName,
			LocalityName:        localityName,
			CountryName:         countryName,
			BasicConstraints:    basicConstraints,
		})
		interCrt = intermediateCA.IntermediateCACrt
		interCnf = intermediateCA.IntermediateCACnf
		interKey = intermediateCA.IntermediateCAKey
	}

	// If output directory is not provided, use the default ca directory
	if outputDir == "" {
		outputDir = defaultCADir
	}
	services.CreateAppCrt(services.CreateAppCrtOptions{
		OutputDir:         outputDir,
		IntermediateCACnf: interCnf,
		IntermediateCACrt: interCrt,
		IntermediateCAKey: interKey,
		RootCACrt:         rootCrt,
		AppName:           appName,
		CommonName:        appDomains[0],
		AltNames:          appDomains,
		P12:               pfx,
	})
}

func createConfigDir(configDir string) {
	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		log.Info("Creating config dir: ", configDir)
		err := os.MkdirAll(configDir, 0700)
		if err != nil {
			log.Fatal(err)
		}
	}
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

	// Version Flag
	rootCmd.Flags().BoolP("version", "v", false, "Print version information.")

	// Select if you want to trust to the root ca
	rootCmd.Flags().BoolVarP(&trustRootCrt, "trust", "t", false, "Trust the root ca crt.")

	// Select if you want to enable debug mode logging
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "verbose logging")

	// Select custom root ca
	rootCmd.Flags().StringVarP(&caName, "root-ca", "r", "default", "Set CA Name.")

	// Select if you want pfx file
	rootCmd.Flags().BoolVarP(&pfx, "pfx", "p", false, "Create pfx file.")

	// Select if you want to renew leaf certificates
	rootCmd.Flags().BoolVarP(&renew, "renew", "R", false, "Renew leaf certificates.")
	rootCmd.Flags().StringVarP(&outputDir, "output", "o", "", "Set output directory for the certs.")

	// Select email ID to use
	rootCmd.Flags().StringVarP(&emailAddress, "email", "e", "test@example.com", "Set email ID to use to generate the certs")

	// Select country
	rootCmd.Flags().StringVarP(&countryName, "country", "c", "TR", "Set country")

	// Select locality
	rootCmd.Flags().StringVarP(&localityName, "locality", "l", "Istanbul", "Set locality")

	// Select state
	rootCmd.Flags().StringVarP(&stateOrProvinceName, "state", "s", "Istanbul", "Set state")

	// Add basic contraints to use
	rootCmd.Flags().StringVarP(&basicConstraints, "basicconstraints", "b", "CA:FALSE", "Set basic constriants")

	// Example usages:
	rootCmd.Example = `Generate a cert under the default root and the default intermediate ca: 
./crtforge crtforgeapp crtforge.com app.crtforge.com api.crtforge.com [flags]

Generate a cert under a root ca named medical and a intermediate ca named frontend:
./crtforge crtforgeapp -r medical -i frontend crtforge.com app.crtforge.com api.crtforge.com [flags]`
}
