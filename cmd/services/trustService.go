package services

import (
	"fmt"
	"os/exec"
	"runtime"
)

func TrustCrt(crtPath string) {
	os := detectOs()
	fmt.Println("Os:", os)
	if isLinux() {
		trustCrtOnLinux(&crtPath)
	} else if isMacos() {
		trustCrtOnMacos(&crtPath)
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
	isCrtTrusted := exec.Command("security", "verify-cert", "-c", *crtPath)
	err := isCrtTrusted.Run()
	if err == nil {
		fmt.Println(*crtPath, "is already trusted")
		return nil
	}
	fmt.Println(*crtPath, "is being trusted on keychain")
	return nil

}
