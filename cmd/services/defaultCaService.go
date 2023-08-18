package services

import (
	"log"
	"os"
)

func CreateCaDir(configDir string, caName string) string {
	defaultCADir := configDir + "/" + caName
	if _, err := os.Stat(defaultCADir); os.IsNotExist(err) {
		err := os.Mkdir(defaultCADir, 0700)
		if err != nil {
			log.Fatal(err)
		}
	}
	return defaultCADir
}
