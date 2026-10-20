//go:build unix

package ca

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// lock takes an exclusive advisory lock on the CA directory so two crtforge
// runs cannot hand out CRL numbers or overwrite state concurrently.
func lock(caDir string) (unlock func(), err error) {
	f, err := os.OpenFile(filepath.Join(caDir, ".lock"), os.O_CREATE|os.O_RDWR, privatePerm)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("another crtforge process is using %s", caDir)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
