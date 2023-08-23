package services

import (
	"fmt"
	"log"
	"os/exec"
	"os/user"
	"runtime"
)

func TrustCrt(crtPath string) {
	os := detectOs()
	fmt.Println("Os:", os)
	if isLinux() {
		trustCrtOnLinux(&crtPath)
	} else if isMacos() {
		err := trustCrtOnMacos(&crtPath)
		if err != nil {
			log.Fatal("Error while trusting cert: ", err)
		}
	} else {
		fmt.Println("Unknown OS. Can not trust the cert.")
	}
}

func isLinux() bool {
	return detectOs() == "linux"
}

func isMacos() bool {
	return detectOs() == "darwin"
}

func detectOs() string {
	return runtime.GOOS
}

func trustCrtOnLinux(crtPath *string) {
	fmt.Println(*crtPath, "is being trusted on Linux...")
}

func trustCrtOnMacos(crtPath *string) error {
	fmt.Println(*crtPath, "is being trusted on MacOS...")
	isCrtTrustedCommand := exec.Command("security", "verify-cert", "-c", *crtPath)
	err := isCrtTrustedCommand.Run()
	if err == nil {
		fmt.Println(*crtPath, "is already found on keychain")
		return nil
	}
	fmt.Println(*crtPath, "will be trusted on keychain")
	sudoPermission := hasSudoPermissions()
	if !sudoPermission {
		return fmt.Errorf("you don't have sudo permissions to add cert to keychain")
	}

	fmt.Println("Sudo permission: ", sudoPermission)

	trustCrtCommand := exec.Command("security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain", *crtPath)
	output, err := trustCrtCommand.CombinedOutput()
	if err != nil {
		fmt.Println("Command output:", string(output))
		return fmt.Errorf("failed to add cert to keychain: %w", err)

	}

	fmt.Println(*crtPath, "has been added to keychain successfully.")
	return nil

}

func hasSudoPermissions() bool {
	currentUser, err := user.Current()
	if err != nil {
		log.Fatalf("[hasSudoPermissions] Unable to get current user: %s", err)
	}
	return currentUser.Username == "root"
}
